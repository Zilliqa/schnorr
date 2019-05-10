#!/bin/bash
# Copyright (C) 2019 Zilliqa
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -e

dir=build

run_clang_format_fix=0
run_clang_tidy_fix=0

for option in "$@"
do
    case $option in
    tsan)
        CMAKE_EXTRA_OPTIONS="-DTHREAD_SANITIZER=ON ${CMAKE_EXTRA_OPTIONS}"
        echo "Build with ThreadSanitizer"
    ;;
    asan)
        CMAKE_EXTRA_OPTIONS="-DADDRESS_SANITIZER=ON ${CMAKE_EXTRA_OPTIONS}"
        echo "Build with AddressSanitizer"
    ;;
    style)
        CMAKE_EXTRA_OPTIONS="-DLLVM_EXTRA_TOOLS=ON ${CMAKE_EXTRA_OPTIONS}"
        run_clang_format_fix=1
        echo "Build with LLVM Extra Tools for coding style check (clang-format-fix)"
    ;;
    linter)
        CMAKE_EXTRA_OPTIONS="-DLLVM_EXTRA_TOOLS=ON ${CMAKE_EXTRA_OPTIONS}"
        run_clang_tidy_fix=1
        echo "Build with LLVM Extra Tools for linter check (clang-tidy-fix)"
    ;;
    *)
        echo "Usage $0 [tsan|asan] [style]"
        exit 1
    ;;
    esac
done

cmake -H. -B${dir} ${CMAKE_EXTRA_OPTIONS} -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTESTS=ON -DCMAKE_INSTALL_PREFIX=..
cmake --build ${dir} -- -j4
./scripts/license_checker.sh
[ ${run_clang_tidy_fix} -ne 0 ] && cmake --build ${dir} --target clang-tidy-fix
[ ${run_clang_format_fix} -ne 0 ] && cmake --build ${dir} --target clang-format-fix
