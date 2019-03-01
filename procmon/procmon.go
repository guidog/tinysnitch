package procmon

import (
	"fmt"
	"github.com/evilsocket/ftrace"
	"github.com/evilsocket/opensnitch/lib"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
)

func GetPIDFromINode(inode int) int {
	expect := fmt.Sprintf("socket:[%d]", inode)
	found := -1
	forEachProcess(func(pid int, path string, args []string) bool {
		// for every descriptor
		fdPath := fmt.Sprintf("/proc/%d/fd/", pid)
		if descriptors, err := ioutil.ReadDir(fdPath); err == nil {
			for _, desc := range descriptors {
				descLink := fmt.Sprintf("%s%s", fdPath, desc.Name())
				// resolve the symlink and compare to what we expect
				if link, err := os.Readlink(descLink); err == nil && link == expect {
					found = pid
					return true
				}
			}
		}
		// keep looping
		return false
	})
	return found
}

func parseCmdLine(proc *Process) {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", proc.ID)); err == nil {
		for i, b := range data {
			if b == 0x00 {
				data[i] = byte(' ')
			}
		}
		args := strings.Split(string(data), " ")
		for _, arg := range args {
			arg = lib.Trim(arg)
			if arg != "" {
				proc.Args = append(proc.Args, arg)
			}
		}
	}
}

func parseEnv(proc *Process) {
	if data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", proc.ID)); err == nil {
		for _, s := range strings.Split(string(data), "\x00") {
			parts := strings.SplitN(lib.Trim(s), "=", 2)
			if parts != nil && len(parts) == 2 {
				key := lib.Trim(parts[0])
				val := lib.Trim(parts[1])
				proc.Env[key] = val
			}
		}
	}
}

func FindProcess(pid int) *Process {
	linkName := fmt.Sprintf("/proc/%d/exe", pid)
	if lib.Exists(linkName) == false {
		return nil
	}
	if link, err := os.Readlink(linkName); err == nil && lib.Exists(link) == true {
		proc := NewProcess(pid, link)
		parseCmdLine(proc)
		parseEnv(proc)
		return proc
	}
	return nil
}

type Process struct {
	ID   int
	Path string
	Args []string
	Env  map[string]string
}

func NewProcess(pid int, path string) *Process {
	return &Process{
		ID:   pid,
		Path: path,
		Args: make([]string, 0),
		Env:  make(map[string]string),
	}
}

const (
	probeName   = "opensnitch_exec_probe"
	syscallName = "do_execve"
)

type procData struct {
	path string
	args []string
}

var (
	subEvents = []string{
		"sched/sched_process_fork",
		"sched/sched_process_exec",
		"sched/sched_process_exit",
	}
	watcher = ftrace.NewProbe(probeName, syscallName, subEvents)
	index   = make(map[int]*procData)
	lock    = sync.RWMutex{}
)

func forEachProcess(cb func(pid int, path string, args []string) bool) {
	lock.RLock()
	defer lock.RUnlock()
	for pid, data := range index {
		if cb(pid, data.path, data.args) == true {
			break
		}
	}
}

func trackProcess(pid int) {
	lock.Lock()
	defer lock.Unlock()
	if _, found := index[pid]; found == false {
		index[pid] = &procData{}
	}
}

func trackProcessArgs(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()
	if d, found := index[e.PID]; found == false {
		index[e.PID] = &procData{
			args: e.Argv(),
			path: "",
		}
	} else {
		d.args = e.Argv()
	}
}

func trackProcessPath(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()
	if d, found := index[e.PID]; found == false {
		index[e.PID] = &procData{
			path: e.Args["filename"],
		}
	} else {
		d.path = e.Args["filename"]
	}
}

func trackProcessExit(e ftrace.Event) {
	lock.Lock()
	defer lock.Unlock()
	delete(index, e.PID)
}

func eventConsumer() {
	for event := range watcher.Events() {
		if event.IsSyscall == true {
			trackProcessArgs(event)
		} else if _, ok := event.Args["filename"]; ok && event.Name == "sched_process_exec" {
			trackProcessPath(event)
		} else if event.Name == "sched_process_exit" {
			trackProcessExit(event)
		}
	}
}

func Start() (err error) {
	// start from a clean state
	watcher.Reset()
	if err = watcher.Enable(); err == nil {
		go eventConsumer()
		// track running processes
		if ls, err := ioutil.ReadDir("/proc/"); err == nil {
			for _, f := range ls {
				if pid, err := strconv.Atoi(f.Name()); err == nil && f.IsDir() {
					trackProcess(pid)
				}
			}
		}
	}
	return
}

func Stop() error {
	return watcher.Disable()
}
