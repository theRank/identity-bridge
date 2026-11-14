// For WeChat devtools, which resolves require('@therank/identity-bridge-client/wechat') by file path and loads it as
// CommonJS. Node and bundlers use the package's exports instead.
module.exports = require('./dist/cjs/wechat.js')
