github下载源码后，可以使用cmake GUI生成vs2019 or 其他版本的解决方案，默认是生成x64的
生成x32的进入的cmake目录，创建一个build32/solution，进入目录执行：
```
cmake -G "Visual Studio 16 2019" -A Win32 ../..
```
x64也可以用这种方式