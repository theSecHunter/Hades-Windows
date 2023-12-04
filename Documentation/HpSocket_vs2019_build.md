HpSocket编译比较简单，下载下来便有很多版本的vs工程，这里需要注意一点，在引用HpSocket.lib时候:
c++-->预处理器-->预处理定义添加：HPSOCKET_STATIC_LIB;