# MIT License
#
# Copyright (c) 2023-2024 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from pathlib import Path

_FILE_DIR = Path(__file__).parent

UDK_TEST_TIMEOUT = 300
UDK_LITE_TAG = "1.0.1"
UDK_LITE_ROOT = "./UDK-Lite/"
UDK_LITE_RELEASE_URL = (f"https://github.com/tuokri/UDK-Lite/releases/download/{UDK_LITE_TAG}/UDK"
                        f"-Lite-{UDK_LITE_TAG}.7z")
FCRYPTO_CLASSES_FILES = _FILE_DIR / "../Classes/*.uc*"
