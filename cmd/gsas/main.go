// GSAS CLI entry point

package main

import (
    "fmt"
    "time"

)

func main() {
    fmt.Println("gsas layer running...")
    for {
        time.Sleep(time.Hour)
    }
}
