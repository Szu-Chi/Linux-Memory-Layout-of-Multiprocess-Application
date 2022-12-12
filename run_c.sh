gcc $1.c -o $1 -lpthread -fPIC
if [ $? -eq 0 ]; then
  ./$1
fi

