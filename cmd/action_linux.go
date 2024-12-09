package cmd

import (
	"fmt"
	"time"

	"github.com/perfect-panel/ppanel-node/common/exec"
	"github.com/spf13/cobra"
)

var (
	startCommand = cobra.Command{
		Use:   "start",
		Short: "Start ppanel-node service",
		Run:   startHandle,
	}
	stopCommand = cobra.Command{
		Use:   "stop",
		Short: "Stop ppanel-node service",
		Run:   stopHandle,
	}
	restartCommand = cobra.Command{
		Use:   "restart",
		Short: "Restart ppanel-node service",
		Run:   restartHandle,
	}
	logCommand = cobra.Command{
		Use:   "log",
		Short: "Output ppanel-node log",
		Run: func(_ *cobra.Command, _ []string) {
			exec.RunCommandStd("journalctl", "-u", "ppanel-node.service", "-e", "--no-pager", "-f")
		},
	}
)

func init() {
	command.AddCommand(&startCommand)
	command.AddCommand(&stopCommand)
	command.AddCommand(&restartCommand)
	command.AddCommand(&logCommand)
}

func startHandle(_ *cobra.Command, _ []string) {
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("ppanel-node启动失败"))
		return
	}
	if r {
		fmt.Println(Ok("ppanel-node已运行，无需再次启动，如需重启请选择重启"))
	}
	_, err = exec.RunCommandByShell("systemctl start ppanel-node.service")
	if err != nil {
		fmt.Println(Err("exec start cmd error: ", err))
		fmt.Println(Err("ppanel-node启动失败"))
		return
	}
	time.Sleep(time.Second * 3)
	r, err = checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("ppanel-node启动失败"))
	}
	if !r {
		fmt.Println(Err("ppanel-node可能启动失败，请稍后使用 ppnode log 查看日志信息"))
		return
	}
	fmt.Println(Ok("ppanel-node 启动成功，请使用 ppnode log 查看运行日志"))
}

func stopHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl stop ppanel-node.service")
	if err != nil {
		fmt.Println(Err("exec stop cmd error: ", err))
		fmt.Println(Err("ppanel-node停止失败"))
		return
	}
	time.Sleep(2 * time.Second)
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error:", err))
		fmt.Println(Err("ppanel-node停止失败"))
		return
	}
	if r {
		fmt.Println(Err("ppanel-node停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息"))
		return
	}
	fmt.Println(Ok("ppanel-node 停止成功"))
}

func restartHandle(_ *cobra.Command, _ []string) {
	_, err := exec.RunCommandByShell("systemctl restart ppanel-node.service")
	if err != nil {
		fmt.Println(Err("exec restart cmd error: ", err))
		fmt.Println(Err("ppanel-node重启失败"))
		return
	}
	r, err := checkRunning()
	if err != nil {
		fmt.Println(Err("check status error: ", err))
		fmt.Println(Err("ppanel-node重启失败"))
		return
	}
	if !r {
		fmt.Println(Err("ppanel-node可能启动失败，请稍后使用 ppnode log 查看日志信息"))
		return
	}
	fmt.Println(Ok("ppanel-node重启成功"))
}
