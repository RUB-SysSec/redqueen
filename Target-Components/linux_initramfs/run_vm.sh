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
qemu-system-x86_64 -kernel bzImage-linux-4.15-rc7 -initrd init_debug_shell.cpio.gz -serial mon:stdio -enable-kvm -k de -m 300  -append "root=/dev/sda console=ttyS0" -nographic 
