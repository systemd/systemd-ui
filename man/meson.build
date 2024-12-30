xsltproc_flags = ['--nonet',
                  '--stringparam', 'funcsynopsis.style', 'ansi',
                  ]

xsl_file = 'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'
xsltproc_cmdline = [xsltproc,
                    '-o', '@OUTPUT',
                    xsltproc_flags,
                    xsl_file,
                    '@INPUT@']

foreach manpage : [['systemadm', '1']]
    name = manpage[0] + '.' + manpage[1]
    custom_target(name,
                  input: manpage[0] + '.xml',
                  output: name,
                  command: xsltproc_cmdline,
                  install: true,
                  install_dir : join_paths(get_option('mandir'), 'man' + manpage[1]))
endforeach
