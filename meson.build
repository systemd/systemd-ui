# SPDX-License-Identifier: LGPL-2.1-or-later

project('systemd-ui', 'vala', 'c',
        version: files('meson.version'),
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'warning_level=2',
        ],
        meson_version : '>= 0.60.0',
        )

project_major_version = meson.project_version().split('.')[0].split('~')[0]
if meson.project_version().contains('.')
        project_minor_version = meson.project_version().split('.')[-1].split('~')[0]
else
        project_minor_version = '0'
endif

prefixdir = get_option('prefix')
datadir = get_option('datadir')
applicationsdir = datadir / 'applications'
appdatadir = datadir / 'appdata'
userunitdir = prefixdir / 'lib/systemd/user'

polkitrulesdir = datadir / 'polkit-1/rules.d'

docdir = get_option('docdir')
if docdir == ''
        docdir = datadir / 'doc/systemd-ui'
endif

#####################################################################

cc = meson.get_compiler('c')
userspace_c_args = []
userspace_c_ld_args = []

# Those generate many false positives, and we do not want to change the code to
# avoid them.
basic_disabled_warnings = [
        '-Wno-inline',
        '-Wno-long-long',
        '-Wno-missing-field-initializers',
        '-Wno-overlength-strings',
        '-Wno-unused-but-set-variable',
        '-Wno-unused-parameter',
        '-Wno-unused-result',
]

possible_common_cc_flags = [
        '-W',
        '-Wvla',
        '-Wundef',
        '-Wformat=2',
        '-Wlogical-op',
        '-Wsign-compare',
        '-Wformat-security',
        '-Wmissing-include-dirs',
        '-Wformat-nonliteral',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Winit-self',
        '-Wdeclaration-after-statement',
        '-Wfloat-equal',
        '-Wmissing-prototypes',
        '-Wmissing-declarations',
        '-Wmissing-noreturn',
        '-Wshadow',
        '-Wendif-labels',
        '-Wcast-align',
        '-Wstrict-aliasing=2',
        '-Wwrite-strings',
        '-Werror=overflow',

        '-fno-common',
        '-fdiagnostics-show-option',
]

possible_common_link_flags = [
        '-fstack-protector',
]

# --as-needed and --no-undefined are provided by meson by default,
# run 'meson configure' to see what is enabled
possible_link_flags = [
        '-Wl,--fatal-warnings',
        '-Wl,-z,now',
        '-Wl,-z,relro',
        '-Wl,--gc-sections',
]

if get_option('b_sanitize') == 'none'
        possible_link_flags += '-Wl,--warn-common'
endif

if cc.get_id() == 'clang'
        possible_common_cc_flags += [
                '-Wno-typedef-redefinition',
                '-Wno-gnu-variable-sized-type-not-at-end',
        ]
endif

possible_cc_flags = [
        '-fno-strict-aliasing',
        '-fstrict-flex-arrays=1',
        '-fvisibility=hidden',
        '-ffunction-sections',
        '-fdata-sections',
]

add_project_arguments(
        cc.get_supported_arguments(
                basic_disabled_warnings,
                possible_common_cc_flags
        ),
        language : 'c')

add_project_link_arguments(
        cc.get_supported_link_arguments(possible_common_link_flags),
        language : 'c')

userspace_c_args += cc.get_supported_arguments(possible_cc_flags)
userspace_c_ld_args += cc.get_supported_link_arguments(possible_link_flags)

#####################################################################
# compilation result tests

have_clock_gettime = cc.has_function('clock_gettime', prefix : '''#include <time.h>''', args : '-D_GNU_SOURCE')
if not have_clock_gettime
    error('`clock_gettime` not found')
endif

#####################################################################

xsltproc = find_program('xsltproc', required: get_option('man').allowed())

#####################################################################

dbus = dependency('dbus-1', version: '>= 1.3.2')
glib = dependency('glib-2.0', version: '> 2.26')
gio_unix = dependency('gio-unix-2.0')
gee = dependency('gee-0.8')
gtk3 = dependency('gtk+-3.0')
libnotify = dependency('libnotify')
posix = meson.get_compiler('vala').find_library('posix')

#####################################################################

userspace = declare_dependency(
        compile_args : userspace_c_args,
        link_args : userspace_c_ld_args,
)

#####################################################################

subdir('src')

#####################################################################

if xsltproc.found()
        subdir('man')
endif

install_data('LICENSE',
             'CODING_STYLE',
             install_dir : docdir)
