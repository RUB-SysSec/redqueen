# 
# This file is part of Redqueen.
#
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Redqueen.  If not, see <http://www.gnu.org/licenses/>.
#

LINUX_VERSION="4.6.2"
LINUX_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-$LINUX_VERSION.tar.xz"
LINUX_MD5="70c4571bfb7ce7ccb14ff43b50165d43"

QEMU_VERSION="2.9.0"
QEMU_URL="http://download.qemu-project.org/qemu-2.9.0.tar.xz"
QEMU_MD5="86c95eb3b24ffea3a84a4e3a856b4e26"

echo "================================================="
echo "           kAFL Redqueen setup script            "
echo "================================================="

echo
echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then
  echo "[-] Error: KVM-PT is supported only on Linux ..."
  exit 1
fi

if ! [ -f /etc/lsb-release ]; then
  echo "[-] Error: Please use Ubuntu (16.04) ..."
  exit 1
fi

for i in dpkg; do
  T=`which "$i" 2>/dev/null`
  if [ "$T" = "" ]; then
    echo "[-] Error: '$i' not found, please install first."
    exit 1
  fi
done

echo "[*] Installing essentials tools ..."
sudo -Eu root apt-get install make gcc libcapstone-dev bc libssl-dev python-pip python-pygraphviz -y gnuplot ruby python libgtk2.0-dev libc6-dev flex -y > /dev/null

echo "[*] Installing build dependencies for QEMU $QEMU_VERSION ..."
sudo -Eu root apt-get build-dep qemu-system-x86 -y > /dev/null

echo "[*] Installing python essentials ..."
sudo -Eu root pip2.7 install mmh3 lz4 psutil > /dev/null 2> /dev/null

echo
echo "[*] Downloading QEMU $QEMU_VERSION ..."
wget -O qemu.tar.gz $QEMU_URL 2> /dev/null

echo "[*] Checking signature of QEMU $QEMU_VERSION ..."
CHKSUM=`md5sum qemu.tar.gz| cut -d' ' -f1`

if [ "$CHKSUM" != "$QEMU_MD5" ]; then
  echo "[-] Error: signature mismatch..."
  exit 1
fi

echo "[*] Unpacking QEMU $QEMU_VERSION ..."
tar xf qemu.tar.gz

echo "[*] Patching QEMU $QEMU_VERSION ..."
patch qemu-$QEMU_VERSION/hmp-commands.hx < QEMU-PT/hmp-commands.hx.patch 
patch qemu-$QEMU_VERSION/monitor.c < QEMU-PT/monitor.c.patch
patch qemu-$QEMU_VERSION/hmp.c < QEMU-PT/hmp.c.patch
patch qemu-$QEMU_VERSION/hmp.h < QEMU-PT/hmp.h.patch 
patch qemu-$QEMU_VERSION/Makefile.target < QEMU-PT/Makefile.target.patch
patch qemu-$QEMU_VERSION/kvm-all.c < QEMU-PT/kvm-all.c.patch 
patch qemu-$QEMU_VERSION/vl.c < QEMU-PT/vl.c.patch
patch qemu-$QEMU_VERSION/configure < QEMU-PT/configure.patch
patch qemu-$QEMU_VERSION/linux-headers/linux/kvm.h < QEMU-PT/linux-headers/linux/kvm.h.patch 
patch qemu-$QEMU_VERSION/include/qom/cpu.h < QEMU-PT/include/qom/cpu.h.patch 
patch qemu-$QEMU_VERSION/hw/misc/applesmc.c < QEMU-PT/hw/misc/applesmc.c.patch


cp QEMU-PT/compile.sh qemu-$QEMU_VERSION/
cp QEMU-PT/hmp-commands-pt.hx qemu-$QEMU_VERSION/
cp QEMU-PT/pt.c qemu-$QEMU_VERSION/
cp QEMU-PT/pt.h qemu-$QEMU_VERSION/
cp -R QEMU-PT/pt/ qemu-$QEMU_VERSION/

echo "[*] Compiling QEMU $QEMU_VERSION ..."
cd qemu-$QEMU_VERSION
echo "-------------------------------------------------"
sh compile.sh 
echo "-------------------------------------------------"
cd ..

echo
echo "[*] Downloading Kernel $LINUX_VERSION ..."
wget -O kernel.tar.gz $LINUX_URL 2> /dev/null

echo "[*] Checking signature of Kernel $LINUX_VERSION ..."
CHKSUM=`md5sum kernel.tar.gz| cut -d' ' -f1`

if [ "$CHKSUM" != "$LINUX_MD5" ]; then
  echo "[-] Error: signature mismatch..."
  echo "$CHKSUM"
  echo "$LINUX_MD5"
  exit 1
fi

echo "[*] Unpacking Kernel $LINUX_VERSION ..."
tar xf kernel.tar.gz

echo "[*] Patching Kernel $LINUX_VERSION ..."
patch linux-$LINUX_VERSION/arch/x86/kvm/Makefile < KVM-PT/arch/x86/kvm/Makefile.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/kvm/Kconfig < KVM-PT/arch/x86/kvm/Kconfig.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/kvm/mmu.c < KVM-PT/arch/x86/kvm/mmu.c.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/kvm/vmx.c < KVM-PT/arch/x86/kvm/vmx.c.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/kvm/svm.c < KVM-PT/arch/x86/kvm/svm.c.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/kvm/x86.c < KVM-PT/arch/x86/kvm/x86.c.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/include/asm/kvm_host.h < KVM-PT/arch/x86/include/asm/kvm_host.h.patch > /dev/null
patch linux-$LINUX_VERSION/arch/x86/include/uapi/asm/kvm.h < KVM-PT/arch/x86/include/uapi/asm/kvm.h.patch > /dev/null
patch linux-$LINUX_VERSION/include/uapi/linux/kvm.h <  KVM-PT/include/uapi/linux/kvm.h.patch > /dev/null

cp KVM-PT/arch/x86/kvm/vmx.h linux-$LINUX_VERSION/arch/x86/kvm/
cp KVM-PT/arch/x86/kvm/vmx_pt.h linux-$LINUX_VERSION/arch/x86/kvm/
cp KVM-PT/arch/x86/kvm/vmx_pt.c linux-$LINUX_VERSION/arch/x86/kvm/

mkdir linux-$LINUX_VERSION/usermode_test/ 2> /dev/null
cp KVM-PT/usermode_test/support_test.c linux-$LINUX_VERSION/usermode_test/
cp KVM-PT/usermode_test/test.c linux-$LINUX_VERSION/usermode_test/
cp KVM-PT/load.sh linux-$LINUX_VERSION/load.sh

echo "[*] Compiling Kernel $LINUX_VERSION ..."
cd linux-$LINUX_VERSION/
yes "" | make oldconfig  > oldconfig.log

if [ ! "` grep \"CONFIG_KVM_VMX_PT=y\" .config | wc -l`" = "1" ]; then
  echo "CONFIG_KVM_VMX_PT=y" >> .config
fi
echo "-------------------------------------------------"
make -j 8
echo "-------------------------------------------------"

echo "KERNEL==\"kvm\", GROUP=\"kvm\"" | sudo -Eu root tee /etc/udev/rules.d/40-permissions.rules > /dev/null

sudo -Eu root groupadd kvm
sudo -Eu root usermod -a -G kvm $USER
sudo -Eu root service udev restart

sudo -Eu root make modules_install
sudo -Eu root make install
cd ../

echo 
echo "[*] Done!"

echo "[*] Compiling Target-Components ..."

cd Target-Components/ 
sh init.sh
cd ..

echo 
echo "[*] Done! Please reboot your system now!"

