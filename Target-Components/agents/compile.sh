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

printf "\nlinux_x86_64 userspace components...\n"
echo "------------------------------------"
cd linux_x86_64
bash compile.sh
cd ../

printf "\nmacOS_x86_64 userspace components...\n"
echo "------------------------------------"
cd macOS_x86_64
bash compile.sh
cd ../

printf "\nwindows_x86_64 userspace components...\n"
echo "------------------------------------"
cd windows_x86_64
bash compile.sh
cd ../

printf "\nlinux_x86_64 userspace components for userspace fuzzing...\n"
echo "------------------------------------"
cd linux_x86_64-userspace
bash compile.sh
cd ../

printf "\ndone...\n"
