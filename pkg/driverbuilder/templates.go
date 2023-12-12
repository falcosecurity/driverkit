// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driverbuilder

var waitForLockScript = `
touch /tmp/download.lock
while true; do
  if [ -f /tmp/download.lock ]; then
    echo "Lock not released yet - waiting for 5 seconds"
    sleep 5
    continue
  fi
  echo "download lock was released, we can exit now"
  break
done
`

var deleteLock = `
rm -f /tmp/download.lock
`

const moduleLockFile = "/tmp/module.lock"
const probeLockFile = "/tmp/probe.lock"

// waitForLockAndCat MUST only output the file, any other output will break
// the download file itself because it goes trough stdout
var waitForLockAndCat = `
while true; do
  if [ -f "$2" ]; then
	sleep 10 1>&/dev/null
	continue
  fi
  break
done
cat "$1"
`
