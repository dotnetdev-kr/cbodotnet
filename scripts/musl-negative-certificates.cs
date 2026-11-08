using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

class NegativeCertificates
{
    static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    static byte[] Serial()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        bytes[0] &= 0x7f;
        bytes[0] |= 1;
        return bytes;
    }

    static CertificateRequest Request(string name, RSA key, bool ca, string dns)
    {
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(ca ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (dns != null)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(dns);
            request.CertificateExtensions.Add(san.Build());
            var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        }
        return request;
    }

    static X509Certificate2 Signed(string name, RSA key, X509Certificate2 issuer, RSA issuerKey, bool ca, string dns, DateTimeOffset before, DateTimeOffset after)
    {
        // The signature-generator overload intentionally permits constructing an
        // invalid-CA fixture. No certificate validation callback is installed.
        var request = Request(name, key, ca, dns);
        var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        using (var cert = request.Create(issuer.SubjectName, generator, before, after, Serial()))
            return cert.CopyWithPrivateKey(key);
    }

    static async Task<bool> Handshake(X509Certificate2 certificate, string name)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task server = Task.Run(async () =>
        {
            using (var socket = await listener.AcceptTcpClientAsync())
            using (var ssl = new SslStream(socket.GetStream(), false))
            {
                try
                {
                    await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false);
                    var marker = new byte[1];
                    await ssl.ReadAsync(marker, 0, 1);
                }
                catch (AuthenticationException) { }
                catch (IOException) { }
            }
        });
        bool success = false;
        try
        {
            using (var socket = new TcpClient())
            {
                await socket.ConnectAsync(IPAddress.Loopback, port);
                using (var ssl = new SslStream(socket.GetStream(), false))
                {
                    try
                    {
                        await ssl.AuthenticateAsClientAsync("localhost", new X509CertificateCollection(), SslProtocols.Tls12, false);
                        success = ssl.IsAuthenticated && ssl.IsEncrypted;
                        await ssl.WriteAsync(new byte[] { 1 }, 0, 1);
                    }
                    catch (AuthenticationException e) { Console.WriteLine("REJECT " + name + ": " + e.GetType().Name + ": " + e.Message); }
                    catch (IOException e) { Console.WriteLine("REJECT " + name + ": " + e.GetType().Name + ": " + e.Message); }
                }
            }
            if (await Task.WhenAny(server, Task.Delay(10000)) != server)
                throw new TimeoutException("TLS server did not finish: " + name);
            await server;
        }
        finally { listener.Stop(); }
        return success;
    }

    static void Require(bool value, string name)
    {
        if (!value) throw new Exception("FAIL " + name);
        Console.WriteLine("PASS " + name);
    }

    static async Task<int> Main()
    {
        string nonce = Guid.NewGuid().ToString("N");
        using (var rootKey = RSA.Create(2048))
        using (var root = Request("probe-root-" + nonce, rootKey, true, null).CreateSelfSigned(Now.AddDays(-14), Now.AddDays(14)))
        using (var publicRoot = new X509Certificate2(root.Export(X509ContentType.Cert)))
        using (var roots = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
        using (var intermediates = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser))
        {
            roots.Open(OpenFlags.ReadWrite);
            intermediates.Open(OpenFlags.ReadWrite);
            roots.Add(publicRoot);
            try
            {
                using (var validKey = RSA.Create(2048))
                using (var valid = Signed("valid", validKey, root, rootKey, false, "localhost", Now.AddDays(-1), Now.AddDays(1)))
                    Require(await Handshake(valid, "trusted-control"), "trusted-control connects with default validation");

                using (var untrustedKey = RSA.Create(2048))
                using (var untrusted = Request("untrusted-" + nonce, untrustedKey, false, "localhost").CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1)))
                    Require(!await Handshake(untrusted, "untrusted-self-signed"), "untrusted-self-signed fails closed");

                using (var expiredKey = RSA.Create(2048))
                using (var expired = Signed("expired", expiredKey, root, rootKey, false, "localhost", Now.AddDays(-3), Now.AddDays(-2)))
                    Require(!await Handshake(expired, "expired"), "expired fails closed");

                using (var wrongKey = RSA.Create(2048))
                using (var wrong = Signed("wrong-host", wrongKey, root, rootKey, false, "wrong.invalid", Now.AddDays(-1), Now.AddDays(1)))
                    Require(!await Handshake(wrong, "wrong-hostname"), "wrong-hostname fails closed");

                using (var badCaKey = RSA.Create(2048))
                using (var badCa = Signed("invalid-ca", badCaKey, root, rootKey, false, null, Now.AddDays(-7), Now.AddDays(7)))
                using (var publicBadCa = new X509Certificate2(badCa.Export(X509ContentType.Cert)))
                using (var leafKey = RSA.Create(2048))
                using (var badChainLeaf = Signed("invalid-ca-leaf", leafKey, badCa, badCaKey, false, "localhost", Now.AddDays(-1), Now.AddDays(1)))
                {
                    intermediates.Add(publicBadCa);
                    try
                    {
                        using (var chain = new X509Chain())
                        {
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                            chain.ChainPolicy.ExtraStore.Add(publicBadCa);
                            bool valid = chain.Build(badChainLeaf);
                            Console.WriteLine("CHAIN invalid-ca: " + String.Join(",", chain.ChainStatus.Select(s => s.Status.ToString())));
                            Require(!valid, "invalid-CA managed chain fails closed");
                            Require(chain.ChainStatus.Any(s => (s.Status & X509ChainStatusFlags.InvalidBasicConstraints) != 0), "invalid-CA native error maps to managed InvalidBasicConstraints");
                        }
                        Require(!await Handshake(badChainLeaf, "invalid-ca"), "invalid-CA TLS fails closed");
                    }
                    finally { intermediates.Remove(publicBadCa); }
                }
            }
            finally { roots.Remove(publicRoot); }
        }
        Console.WriteLine("PASS all certificate cases; no remote validation callback");
        return 0;
    }
}
