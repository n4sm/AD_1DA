while [ 1 ]; do md5sum ./$1 && ./$1 > /dev/null; done;
