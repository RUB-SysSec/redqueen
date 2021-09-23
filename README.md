# Red­queen: Fuz­zing with In­put-to-Sta­te Cor­re­spon­dence 
<a href="https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/"> <img align="right" width="200"  src="rq_paper.png"> </a>

Redqueen is a fast general purpose fuzzer for x86 binary applications. It can automatically overcome checksums and magic bytes without falling back to complex and fragile program analysis techniques, such as symbolic execution. It works by observing the arguments to function calls and compare instructions via virtual machine introspection. Observed values are used to provide inputs specific mutations. More details can be found in the paper. This fuzzer is built upon [kAFL](https://github.com/RUB-SysSec/kAFL) and requires support for Intel VT-x as well as Intel Processor Trace. 

The <a href="https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/">Paper</a>, <a href="https://www.youtube.com/watch?v=9JpanJ29r_U">Talk</a> and <a href="https://hexgolems.com/talks/redqueen.pdf">Slides</a> describing Redqueen were published at NDSS 2019. 

_Note_: Intel now actively maintains a better version of kAFL/Redqueen/Grimoire here: https://github.com/IntelLabs/kAFL 

## BibTex:
```
@inproceedings{redqueen,
  title={REDQUEEN: Fuzzing with Input-to-State Correspondence},
  author={Aschermann, Cornelius and Schumilo, Sergej and Blazytko, Tim and Gawlik, Robert and Holz, Thorsten},
  booktitle={Symposium on Network and Distributed System Security (NDSS)},
  year={2019},
}
```

### Initial Setup
To install redqueen run `install.sh`

```
cd ~/redqueen/
sh install.sh
```

This will setup everything, assuming an Ubuntu 16.04.

Fuzzing with Redqueen is a two stage process. First, the target application is packed:

```
python ~/redqueen/kAFL-Fuzzer/kafl_user_prepare.py --recompile -args=/A -file=/A ~/redqueen/Evaluation/lava/binaries/who ~/redqueen/Evaluation/lava/packed/who/ m64
```

Use `kafl_info.py` and the generated `info` executable to get the address ranges of your fuzzing target:

```
python kafl_info.py Kernel  \
~/redqueen/Target-Components/linux_initramfs/bzImage-linux-4.15-rc7 \
~/redqueen/Target-Components/linux_initramfs/init.cpio.gz \
~/redqueen/Evaluation/lava/packed/who/who_info \
500
```

Then the packed binary can be fuzzed.

```
python kafl_fuzz.py Kernel \
~/redqueen/Target-Components/linux_initramfs/bzImage-linux-4.15-rc7 \
~/redqueen/Target-Components/linux_initramfs/init.cpio.gz \
~/redqueen/Evaluation/lava/packed/who/who_fuzz  \
500 \
~/redqueen/Evaluation/lava/packed/uninformed_seeds \
/tmp/kafl_workdir -ip0 0x400000-0x47c000 -t10 -hammer_jmp_tables -n -D -r -l -v -p1
```

 <a> <img  src="fuzzer.gif"> </a>


### Trophies
* [CVE-2018-12641](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763099) (binutils nm-new)
* [CVE-2018-12697](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils libiberty)
* [CVE-2018-12698](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils libiberty)
* [CVE-2018-12699](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils objdump)
* [CVE-2018-12700](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763102) (binutils objdump)
* [CVE-2018-12928](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763384) (linux hfs.ko)
* [CVE-2018-12929](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12930](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12931](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1763403) (linux ntfs.ko)
* [CVE-2018-12932](https://bugs.launchpad.net/ubuntu/+source/wine/+bug/1764719) (wine)
* [CVE-2018-12933](https://bugs.launchpad.net/ubuntu/+source/wine/+bug/1764719) (wine)
* [CVE-2018-12934](https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1763101) (binutils cxxfilt)
* [CVE-2018-12935](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12935)  (ImageMagick)
* [CVE-2018-14337](https://github.com/mruby/mruby/issues/4062) (mruby)
* [CVE-2018-14566](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14566) (bash)
* [CVE-2018-14567](https://access.redhat.com/security/cve/cve-2018-14567) (xml2)
* [CVE-2018-16747](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16747) (fdk-aac)
* [CVE-2018-16748](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16748) (fdk-aac)
* [CVE-2018-16749](https://github.com/ImageMagick/ImageMagick/issues/1119) (ImageMagick)
* [CVE-2018-16750](https://github.com/ImageMagick/ImageMagick/issues/1118) (ImageMagick)
* [CVE-2018-20116](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20116) (tcpdump)
* [CVE-2018-20117](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20117) (tcpdump)
* [CVE-2018-20118](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20118) (tcpdump)
* [CVE-2018-20119](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20119) (tcpdump)

## License

AGPLv3

**Free Software, Hell Yeah!**
