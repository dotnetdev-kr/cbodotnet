using System;using System.Reflection;using System.Runtime.CompilerServices;
class P{static int counter;
 [MethodImpl(MethodImplOptions.NoInlining)]static int Normal(){int value=1;try{Console.WriteLine("TRY");value+=2;}finally{Console.WriteLine("FINALLY");value+=10;}return value;}
 [MethodImpl(MethodImplOptions.NoInlining)]static int Return(){try{return 7;}finally{counter=8;Console.WriteLine("FINALLY RETURN");}}
 [MethodImpl(MethodImplOptions.NoInlining)]static void Throw(){try{throw new Exception("probe");}finally{counter=9;Console.WriteLine("FINALLY THROW");}}
 [MethodImpl(MethodImplOptions.NoInlining)]static int Catch(){try{throw new Exception("catch");}catch(Exception){return 17;}}
 [MethodImpl(MethodImplOptions.NoInlining)]static int Loop(){int value=0;for(int i=0;i<10;i++){try{value++;}finally{counter++;}}return value;}
 [MethodImpl(MethodImplOptions.NoInlining)]static int Residue2(){try{return 7;}finally{counter=9;}}
 static int Main(string[]args){Console.WriteLine("START "+args[0]);
  if(args[0]=="identity"){Console.WriteLine("RUNTIME "+Environment.Version);return Environment.Version.ToString()=="5.0.17"?0:10;}
  if(args[0]=="metadata"){foreach(string name in new[]{"Normal","Return","Throw","Catch","Loop","Residue2"}){var m=typeof(P).GetMethod(name,BindingFlags.Static|BindingFlags.NonPublic);var b=m.GetMethodBody();Console.WriteLine("METHOD "+name+" IL "+BitConverter.ToString(b.GetILAsByteArray()));if(b.ExceptionHandlingClauses.Count!=1)throw new Exception("Missing EH: "+name);foreach(var c in b.ExceptionHandlingClauses)Console.WriteLine("EH "+name+" FLAGS "+(int)c.Flags+" TRY "+c.TryOffset+" "+c.TryLength+" HANDLER "+c.HandlerOffset+" "+c.HandlerLength );}var residues=new System.Collections.Generic.HashSet<int>();foreach(string name in new[]{"Normal","Return","Throw","Catch","Loop","Residue2"})residues.Add(typeof(P).GetMethod(name,BindingFlags.Static|BindingFlags.NonPublic).GetMethodBody().GetILAsByteArray().Length%4);if(residues.Count!=4)throw new Exception("All IL end alignment residues must be exercised");Console.WriteLine("PASS metadata EH=6 residues=0,1,2,3");return 0;}
  if(args[0]=="normal"){int v=Normal();Console.WriteLine("RESULT "+v);return v==13?0:2;}
  if(args[0]=="return"){int v=Return();Console.WriteLine("RESULT "+v+" COUNTER "+counter);return v==7&&counter==8?0:3;}
  if(args[0]=="throw"){try{Throw();}catch(Exception e){Console.WriteLine("CAUGHT "+e.Message+" COUNTER "+counter);}return counter==9?0:4;}
  if(args[0]=="catch"){int v=Catch();Console.WriteLine("RESULT "+v);return v==17?0:5;}
  if(args[0]=="loop"){int v=Loop();Console.WriteLine("RESULT "+v+" COUNTER "+counter);return v==10&&counter==10?0:6;}
  if(args[0]=="residue2"){int v=Residue2();Console.WriteLine("RESULT "+v+" COUNTER "+counter);return v==7&&counter==9?0:8;}
  return S.Run(args[0]);}}

class S {
 static int start,value;static readonly object gate=new object();
 static System.Threading.SpinLock spin=new System.Threading.SpinLock(false);
 static readonly System.Collections.Concurrent.ConcurrentDictionary<int,object> dictionary=new System.Collections.Concurrent.ConcurrentDictionary<int,object>();
 static void Body(string mode,int worker) {
  while(System.Threading.Volatile.Read(ref start)==0)System.Threading.Thread.SpinWait(1);
  for(int i=0;i<10000;i++) {
   if(mode=="lock"){lock(gate){value++;}}
   else if(mode=="spinlock"){bool taken=false;try{spin.Enter(ref taken);value++;}finally{if(taken)spin.Exit();}}
   else if(mode=="dictionary-same"){dictionary.TryAdd(i%64,new object());}
   else if(mode=="dictionary-distinct"){dictionary.TryAdd(i*2+worker,new object());}
   else throw new Exception(mode);
  }
 }
 public static int Run(string mode) {
  if(mode!="lock"&&mode!="spinlock"&&mode!="dictionary-same"&&mode!="dictionary-distinct")return 9;
  var a=new System.Threading.Thread(()=>Body(mode,0)){IsBackground=true};
  var b=new System.Threading.Thread(()=>Body(mode,1)){IsBackground=true};
  a.Start();b.Start();System.Threading.Volatile.Write(ref start,1);
  bool x=a.Join(10000),y=b.Join(10000);
  int count=mode=="dictionary-same"?64:mode=="dictionary-distinct"?20000:0;
  int expected=count==0?20000:0;
  if(!x||!y||value!=expected||dictionary.Count!=count) {
   Console.WriteLine("FAIL "+mode+" joins="+x+","+y+" value="+value+" count="+dictionary.Count);return 7;
  }
  Console.WriteLine("PASS "+mode+" value="+value+" count="+dictionary.Count);return 0;
 }
}
