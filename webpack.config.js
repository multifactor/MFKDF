const path = require('path');

module.exports = {
    mode: 'production',
    entry: './src/index.js',
    output: {
        path: path.resolve(__dirname),
        publicPath: '/',
        filename: 'mfkdf.js',
        library: {
          name: 'mfkdf',
          type: 'umd'
        }
    },
    optimization: {
        minimize: false
    },
    module: {
        noParse: /\.wasm$/,
        rules: [
            {
                test: /\.wasm$/,
                loader: 'base64-loader',
                type: 'javascript/auto',
            },
        ],
    },
    resolve: {
        fallback: {
            path: false,
            fs: false,
            Buffer: false,
            process: false,
            crypto: require.resolve("crypto-browserify"),
            buffer: require.resolve("buffer/"),
            stream: require.resolve("stream-browserify")
        },
    },
};
