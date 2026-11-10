# Third-party notices

asa is an independent project. It is not affiliated with, endorsed by or supported by
Microsoft Corporation. "Attack Surface Analyzer" is the name of a Microsoft project.

## Microsoft Attack Surface Analyzer

https://github.com/microsoft/AttackSurfaceAnalyzer

Some of asa's default rules (`rules/default.yaml`) are adapted from that project's
`analyses.json`. It is distributed under the following license:

```text
Copyright (c) Microsoft Corporation. All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Rust crates

`asa.exe` statically links Rust crates (for example rusqlite with a bundled SQLite,
clap, serde, regex, tiny_http, the `windows` and `windows-sys` crates). Each is
distributed under the MIT or Apache-2.0 license, or both; SQLite is in the public domain.
The exact list and versions are in `Cargo.lock`, and each crate's license text is in its
published package.
