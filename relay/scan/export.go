// 该包下仅提供给iocgo工具使用的，不需要理会 Injects 的错误，在编译过程中生成

package scan

import (
	"github.com/iocgo/sdk"

	"chatgpt-adapter/relay/hf"
	"chatgpt-adapter/relay/llm/blackbox"
	"chatgpt-adapter/relay/llm/coze"
	"chatgpt-adapter/relay/llm/lmsys"
	"chatgpt-adapter/relay/llm/v1"
	"chatgpt-adapter/relay/llm/you"
	"chatgpt-adapter/relay/pg"
)

func Injects(container *sdk.Container) (err error) {
	err = v1.Injects(container)
	if err != nil {
		return
	}

	err = coze.Injects(container)
	if err != nil {
		return
	}

	err = you.Injects(container)
	if err != nil {
		return
	}

	err = lmsys.Injects(container)
	if err != nil {
		return
	}

	err = pg.Injects(container)
	if err != nil {
		return
	}

	err = hf.Injects(container)
	if err != nil {
		return
	}

	err = blackbox.Injects(container)
	if err != nil {
		return
	}
	return
}
