Test corpus from:
http://moyix.blogspot.com/2016/10/the-lava-synthetic-bug-corpora.html

This distribution contains the automatically generated bug corpora used
in the paper, "LAVA: Large-scale Automated Vulnerability Addition".

LAVA-1 is a corpus consisting of 69 versions of the "file" utility, each
of which has had a single bug injected into it. Each bug is a named
branch in a git repository. The triggering input can be found in the
file named CRASH_INPUT. To run the validation, you can use validate.sh,
which builds each buggy version of file and evaluates it on the
corresponding triggering input.

LAVA-M is a corpus consisting of four GNU coreutils programs (base64,
md5sum, uniq, and who), each of which has had a large number of bugs
added. Each injected, validated bug is listed in the validated_bugs
file, and the corresponding triggering inputs can be found in the inputs
subdirectory. To run the validation, you can use the validate.sh script,
which builds the buggy utility and evaluates it on triggering and
non-triggering inputs.

For both corpora, the "backtraces" subdirectory contains the output of
gdb's backtrace command for each bug.
