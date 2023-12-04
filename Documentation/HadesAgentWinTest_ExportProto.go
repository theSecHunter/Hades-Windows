package main

import "C"
import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK/transport/protocol"
)

func main() {
	binaryPath := "D:/Hades/Hades-Windows/bin/x64/Debug/HadesSvc_d64.exe"
	args := []string{""}

	ppReader, ppWriter, Stderr := os.Pipe()
	if Stderr != nil {
		fmt.Printf("create cmd stdoutpipe failed,error:%s\n", Stderr)
		os.Exit(1)
	}
	defer ppWriter.Close()

	ppReader1, ppWriter1, Stderr1 := os.Pipe()
	if Stderr1 != nil {
		fmt.Printf("create cmd stdoutpipe failed,error:%s\n", Stderr)
		os.Exit(1)
	}
	defer ppReader1.Close()

	bufio.NewReaderSize(ppReader, 1024*1024)
	bufio.NewWriterSize(ppWriter1, 512*1024)

	procAttr := new(os.ProcAttr)
	procAttr.Files = []*os.File{ppReader, ppWriter1, os.Stderr}
	pros, err := os.StartProcess(binaryPath, args, procAttr)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("son ", pros.Pid)
	time.Sleep(1 * time.Second)

	task := &protocol.Task{
		DataType:   200,
		ObjectName: "",
		Data:       "",
		Token:      "",
	}
	size := task.Size()
	var buf = make([]byte, 4+size)
	if _, err = task.MarshalToSizedBuffer(buf[4:]); err != nil {
		return
	}
	binary.LittleEndian.PutUint32(buf[:4], uint32(size))
	_, err = ppWriter.Write(buf)

	var buffer []byte = make([]byte, 4096)
	for {
		n, err := ppReader1.Read(buffer)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("pipi has Closed\n")
				break
			} else {
				fmt.Println("Read content failed")
			}
		}
		fmt.Print(string(buffer[:n]))
	}
	defer ppReader.Close()

}

//export testPackteDeCode
func testPackteDeCode(data string, taskid int32, protobuf *string) (err error) {
	record := &protocol.Record{
		DataType:  taskid,
		Timestamp: time.Now().Unix(),
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data_type": strconv.Itoa(int(taskid)),
				"udata":     data,
			},
		}}
	var buf []byte
	buf, err = record.Marshal()
	if err != nil {
		return err
	}
	*protobuf = string(buf[:])
	return err
}
