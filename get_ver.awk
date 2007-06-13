# fetch libssh2 version number from input file and write them to STDOUT
BEGIN {
  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define LIBSSH2_VERSION[ |\t]+"[^"]+"/)) {
      my_ver_str = substr($3, 2, length($3) - 2);
      split(my_ver_str, v, ".");
      if (v[3])
        gsub("[^0-9].*$", "", v[3]);
      else
        v[3] = 0;
      if (v[2])
        gsub("[^0-9].*$", "", v[2]);
      else
        v[2] = 0;
      my_ver = v[1] "," v[2] "," v[3];
    }
  }
  print "LIBSSH2_VERSION = " my_ver "";
  print "LIBSSH2_VERSION_STR = " my_ver_str "";
}
