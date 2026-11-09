import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_bootstrap_native_source_inputs as M


class BootstrapNativeSources(unittest.TestCase):
    def original(self,raw=b'original C source\n',mode='100644'):
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        return dict(mode=mode,baseline=dict(mode=mode,blob=blob))

    def trace_fixture(self):
        originals={name:dict(raw=('original '+name).encode(),gitBlob='a'*40) for name in M.GENERATOR_NAMES}
        inputs={name:dict(M.fingerprint(row['raw']),gitBlob=row['gitBlob']) for name,row in originals.items()}
        files={'generated/lttng/file'+str(i)+('.cpp' if i<4 else '.h'):dict(raw=('source'+str(i)).encode(),mode='100644') for i in range(12)}
        outputs={name[len('generated/'):]:dict(mode=0o644,**M.fingerprint(row['raw'])) for name,row in files.items()}
        return originals,files,dict(generatorInputs=inputs,generatorOutputs=outputs)

    def test_original_cpp_bytes_and_mode(self):
        raw=b'original C source\n';self.assertEqual(M.original_runtime_bytes('source.c',self.original(raw),raw,{}),raw)

    def test_self_consistent_executable_bit_change_rejected(self):
        raw=b'original C source\n';row=self.original(raw);row['mode']='100755'
        with self.assertRaisesRegex(ValueError,'mode must match'):M.original_runtime_bytes('source.c',row,raw,{})

    def test_undeclared_cpp_edit_rejected(self):
        with self.assertRaisesRegex(ValueError,'undeclared'):M.original_runtime_bytes('source.c',self.original(),b'changed source\n',{})

    def test_cpp_line_endings_are_strict(self):
        with self.assertRaisesRegex(ValueError,'undeclared'):M.original_runtime_bytes('source.c',self.original(),b'original C source\r\n',{})

    def test_complete_generator_fixture(self):
        original,files,p=self.trace_fixture();self.assertEqual(M.trace_sources(original,files,p)['generatedFiles'],12)

    def test_self_consistent_generated_cpp_bytes_rejected(self):
        original,files,p=self.trace_fixture();files['generated/lttng/file0.cpp']['raw']+=b'\nchanged'
        with self.assertRaisesRegex(ValueError,'reconstructed'):M.trace_sources(original,files,p)

    def test_generated_executable_bit_rejected(self):
        original,files,p=self.trace_fixture();files['generated/lttng/file0.cpp']['mode']='100755'
        with self.assertRaisesRegex(ValueError,'reconstructed'):M.trace_sources(original,files,p)

    def test_generated_extra_file_rejected(self):
        original,files,p=self.trace_fixture();files['generated/lttng/extra.cpp']=dict(raw=b'rogue',mode='100644')
        with self.assertRaisesRegex(ValueError,'reconstructed'):M.trace_sources(original,files,p)

    def test_original_generator_module_edit_rejected(self):
        original,files,p=self.trace_fixture();original[M.GENERATOR_NAMES[0]]['raw']+=b'changed'
        with self.assertRaisesRegex(ValueError,'authenticated'):M.trace_sources(original,files,p)

    def test_crypto_complete_selection_required(self):
        with self.assertRaisesRegex(ValueError,'Complete original'):M.crypto_sources({}, {})

    def graph_fixture(self):
        names=['source'+str(i)+'.c' for i in range(27)];prefix='/delivery/reports/prepare/bootstrap-crypto/'
        units=[prefix+'source/'+M.CRYPTO+n for n in names]+[prefix+'driver/version.c']
        make=''.join('\tcd /obj && /usr/lib/llvm20/bin/clang -O3 -c '+name+'\n' for name in units)
        paths={'obj/crypto/CMakeFiles/objlib.dir/build.make':make,
            'obj/crypto/CMakeFiles/objlib.dir/flags.make':'C_FLAGS = -O3\n',
            'obj/crypto/CMakeFiles/System.Security.Cryptography.Native.OpenSsl.dir/link.txt':'original link\n',
            'obj/Common/pal_config.h':'original Common header\n','obj/crypto/pal_crypto_config.h':'original crypto header\n'}
        files={name:dict(raw=raw.encode(),mode='100644') for name,raw in paths.items()}
        policy=dict(cryptoGeneratedBuildGraph={name:dict(mode=0o644,**M.fingerprint(row['raw'])) for name,row in files.items()},
            generatedIncludeDirectoryFiles={name:0o644 for name in files})
        files['source/'+M.CRYPTO+'CMakeLists.txt']=dict(raw=('set(NATIVECRYPTO_SOURCES\n'+'\n'.join(names)+'\n)\n').encode(),mode='100644')
        return files,policy

    def test_complete_object_source_graph_fixture(self):
        files,p=self.graph_fixture();self.assertEqual(M.crypto_graph(files,p)['originalCryptoCompilationUnits'],27)

    def test_generated_build_flags_change_rejected(self):
        files,p=self.graph_fixture();files['obj/crypto/CMakeFiles/objlib.dir/flags.make']['raw']=b'C_FLAGS = -O0\n'
        with self.assertRaisesRegex(ValueError,'Exact recorded'):M.crypto_graph(files,p)

    def test_generated_config_header_change_rejected(self):
        files,p=self.graph_fixture();files['obj/Common/pal_config.h']['raw']+=b'\n#define ROGUE 1\n'
        with self.assertRaisesRegex(ValueError,'Exact recorded'):M.crypto_graph(files,p)

    def test_extra_nested_stock_header_shadow_rejected(self):
        files,p=self.graph_fixture();files['obj/crypto/openssl/ssl.h']=dict(raw=b'rogue header',mode='100644')
        with self.assertRaisesRegex(ValueError,'extra shadow headers'):M.crypto_graph(files,p)

    def test_x64_requires_separate_observed_positive(self):
        with self.assertRaisesRegex(ValueError,'x64 positive is pending'):
            M.validate(ROOT,{},dict(sdkVersion='5.0.214',architecture='x64'))


if __name__=='__main__':unittest.main()
