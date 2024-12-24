import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import { v4 as uuidv4 } from 'uuid';
import zlib from 'zlib';
import { promisify } from 'util';
import cors from 'cors';





// ... 其余代码保持不变 ...

const gzip = promisify(zlib.gzip);
const app = express();
const port = 3000;
// 添加cors中间件配置
app.use(cors({
    origin: '*', // 允许所有来源访问，生产环境建议设置具体的域名
    methods: ['GET', 'POST', 'OPTIONS'], // 允许的HTTP方法
    allowedHeaders: ['Content-Type', 'Authorization'], // 允许的请求头
    credentials: true // 允许发送cookie
}));
// 修改 body-parser 配置，增加限制大小
app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb', extended: true}));
app.use(bodyParser.json());

app.get('/test', (req, res) => {
    console.log('Test endpoint hit!');
    res.json({ message: 'Test successful' });
});
// OpenAI-style chat completions endpoint
// ... existing code ...
// ... existing code ...
// 添加一个全局变量来追踪当前使用的密钥索引
let currentKeyIndex = 0;
// 修改 model list endpoint
app.get('/v1/models', async (req, res) => {
    const models = [
        {
            id: "claude-3.5-sonnet",
            object: "model",
            created: 1706745938,
            owned_by: "windsurf"
        }
    ];

    res.json({
        object: "list",
        data: models
    });
});
// Helper function to encode length similar to the Python version
function encodeLength(length) {
    if (length < 128) {
        return Buffer.from([length]);
    } else if (length < 16384) {
        const lowByte = (length & 0x7F) | 0x80;
        const highByte = (length >> 7) & 0x7F;
        return Buffer.from([lowByte, highByte]);
    } else {
        const lowByte = (length & 0x7F) | 0x80;
        const midByte = ((length >> 7) & 0x7F) | 0x80;
        const highByte = (length >> 14) & 0xFF;
        return Buffer.from([lowByte, midByte, highByte]);
    }
}

function extractText(decompressedBuffer) {
    // Split by 0x1a byte marker
    const parts = decompressedBuffer.toString('binary').split('\x1a');
    if (parts.length <= 1) {
        return '';
    }
    
    // Get the last part that contains the actual message
    const lastPart = Buffer.from(parts[parts.length - 1], 'binary');
    
    // Remove first and last byte
    try {
        console.log(lastPart);
        let textBuffer = lastPart[0] === 0x0a ? 
            lastPart.slice(0, -1) : 
            lastPart.slice(1, -1);
        const decoder = new TextDecoder('utf-8', { fatal: true });
        let text = decoder.decode(textBuffer);
        console.log(text);
        return text.replace(/[ ]+$/g, '');
    } catch (error) {
        const textBuffer = lastPart.slice(0, -1);
        // Convert to string and remove only trailing spaces
        const text = textBuffer.toString('utf8');
        console.log(1111);
        console.log(text);
        return text.replace(/[ ]+$/g, '');
    }
}

async function createRequestPayload(messages, jwt, {
    systemPrompt = "you are Claude",
    temperature = 0.9,
    top_p = 0.9,
    presence_penalty = 1.0,
    frequency_penalty = 1.0
} = {}) {

    if (messages.length % 2 === 0) {
        messages.unshift({ role: "system", content: systemPrompt });
    }

    const prexByte = Buffer.from([0x0a, 0x08, ...Buffer.from("windsurf"), 0x12, 0x06, ...Buffer.from("1.30.0"),
        0x1a, ...Buffer.from("$6972fdaf-4f45-4aad-9154-45c4da494963"), 0x22, 0x02, ...Buffer.from("en"), 0x2a, 0x8d, 0x01,
        ...Buffer.from('{"Os":"windows","Arch":"amd64","Version":"6.3","ProductName":"Windows 10 Pro","MajorVersionNumber":10,"MinorVersionNumber":0,"Build":"19045"}'),
        0x3a, 0x0f, ...Buffer.from("Windsurf 1.94.0"), 0x42, 0xbe, 0x01,
        ...Buffer.from('{"NumSockets":1,"NumCores":6,"NumThreads":12,"VendorID":"GenuineIntel","Family":"205","Model":"claude-3.5-sonnet","ModelName":"Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz","Memory":34219245568}'),
        0x62, 0x08, ...Buffer.from("windsurf"), 0xaa, 0x01
    ]);

    const jwtByte = Buffer.from(jwt);
    const jwtLengthByte = encodeLength(jwtByte.length);
    const prexLengthByte = encodeLength(jwtByte.length+jwtLengthByte.length+prexByte.length);
    const systemPromptByte = Buffer.from(systemPrompt);
    const systemPromptLengthByte = encodeLength(systemPromptByte.length);

    const firstMessage = messages.shift();
    const promptBytes = Buffer.from(firstMessage.content);
    const promptLengthByte = encodeLength(promptBytes.length);
    const promptLength1Byte = encodeLength(3 + promptBytes.length + promptLengthByte.length);

    let finalPromptBytes = Buffer.concat([
        Buffer.from([0x1a]),
        promptLength1Byte,
        Buffer.from([0x10, 0x01, 0x1a]),
        promptLengthByte,
        promptBytes
    ]);
    let isUser = false;
    for (const message of messages) {
        const msgBytes = Buffer.from(message.content);
        const msgLengthByte = encodeLength(msgBytes.length);
        const msgLength1Byte = encodeLength(3 + msgBytes.length + msgLengthByte.length);

        if (isUser) {
            // User message format
            finalPromptBytes = Buffer.concat([
                finalPromptBytes,
                Buffer.from([0x8b, 0x03, 0x28, 0x01, 0x1a]),
                msgLength1Byte,
                Buffer.from([0x10, 0x01, 0x1a]),
                msgLengthByte,
                msgBytes
            ]);
            isUser = false;
        } else {
            // Assistant message format
            finalPromptBytes = Buffer.concat([
                finalPromptBytes,
                Buffer.from([0x28, 0x01, 0x42, 0x02, 0x08, 0x01, 0x1a]),
                msgLength1Byte,
                Buffer.from([0x10, 0x02, 0x1a]),
                msgLengthByte,
                msgBytes,
                Buffer.from([0x20]) // Space at the end
            ]);
            isUser = true;
        }
    }




    const configBytes = Buffer.concat([
        Buffer.from([0x28, 0x01, 0x42, 0x02, 0x08, 0x01, 0x30, 0xa6, 0x01, 0x38, 0x05, 0x42, 0x76, 0x08, 0x01, 0x10, 0x80, 0x40, 0x18, 0xc8, 0x01]),
        // temperature
        Buffer.from([0x29]), Buffer.from(new Float64Array([temperature]).buffer),
        // top_p
        Buffer.from([0x38, 0x32, 0x41]), Buffer.from(new Float64Array([top_p]).buffer),
        // presence_penalty
        Buffer.from([0x31]), Buffer.from(new Float64Array([presence_penalty]).buffer),
        // 特殊标记
        Buffer.from([0x4a, 0x08]), Buffer.from("<|user|>"),
        Buffer.from([0x4a, 0x07]), Buffer.from("<|bot|>"),
        Buffer.from([0x4a, 0x13]), Buffer.from("<|context_request|>"),
        Buffer.from([0x4a, 0x0d]), Buffer.from("<|endoftext|>"),
        Buffer.from([0x4a, 0x0f]), Buffer.from("<|end_of_turn|>"),
        // frequency_penalty
        Buffer.from([0x59]), Buffer.from(new Float64Array([frequency_penalty]).buffer)
    ]);

    const toolBytes = Buffer.from([
        0x52, 0x98, 0x02, 0x0a, 0x05, ...Buffer.from("never"), 0x12, 0x00, 0x1a, 0x8c, 0x02,
        ...Buffer.from('{"$schema":"","properties":{"AbsolutePath":{"type":"string","description":""},"StartLine":{"type":"integer","description":""},"EndLine":{"type":"integer","description":""}},"additionalProperties":false,"type":"object","required":["AbsolutePath","StartLine","EndLine"]}')
    ]);

    const totalByte = Buffer.concat([
        Buffer.from([0x0a]),
        prexLengthByte,
        prexByte,
        jwtLengthByte,
        jwtByte,
        Buffer.from([0x12]),
        systemPromptLengthByte,
        systemPromptByte,
        finalPromptBytes,
        configBytes,
        // toolBytes,
        Buffer.from([0x6a, 0x02, 0x08, 0x01])
    ]);
    console.log(totalByte);
    const compressed = await gzip(totalByte);
    const lengthBytes = Buffer.alloc(2);
    lengthBytes.writeUInt16BE(compressed.length);
    
    return Buffer.concat([Buffer.from([0x01, 0x00, 0x00]), lengthBytes, compressed]);
}

// Add global JWT cache
const jwtCache = new Map();
const JWT_CACHE_DURATION = 3600000; // 1 hour in milliseconds

// Add this function to get JWT from UID
async function getJwtFromUid(uid) {
    // Check cache first
    const cachedJwt = jwtCache.get(uid);
    if (cachedJwt && cachedJwt.timestamp > Date.now() - JWT_CACHE_DURATION) {
        return cachedJwt.jwt;
    }

    // Convert uid to hex
    const uidHex = Buffer.from(uid).toString('hex');
    // Construct request payload
    const payload = Buffer.concat([
        Buffer.from([0x0A, 0x57, 0x0A, 0x08]), Buffer.from("windsurf"),
        Buffer.from([0x12, 0x06]), Buffer.from("1.30.0"),
        Buffer.from([0x1A, 0x24]), Buffer.from(uidHex,'hex'),
        Buffer.from([0x22, 0x02]), Buffer.from("en"),
        Buffer.from([0x3A, 0x0F]), Buffer.from("Windsurf 1.94.0b"),
        Buffer.from([0x08]), Buffer.from("windsurf")
    ]);
    const response = await fetch('https://server.codeium.com/exa.auth_pb.AuthService/GetUserJwt', {
        method: 'POST',
        headers: {
            'Host': 'server.codeium.com',
            'User-Agent': 'connect-go/1.16.2 (go1.23.2 X:nocoverageredesign)',
            'Accept-Encoding': 'gzip',
            'Connect-Protocol-Version': '1',
            'Connect-Timeout-Ms': '30000',
            'Content-Type': 'application/proto',
            'Content-Length': payload.length.toString()
        },
        body: payload
    });

    if (!response.ok) {
        throw new Error(`Failed to get JWT: ${response}`);
    }

    const responseData = await response.arrayBuffer();
    // Extract JWT from response (assuming it's in the response data)
    const jwt = Buffer.from(responseData).slice(3).toString('utf8');
    
    // Cache the JWT
    jwtCache.set(uid, {
        jwt,
        timestamp: Date.now()
    });

    return jwt;
}

// 添加在文件开头的配置部分
const CONFIG = {
    CHAT_TIMEOUT: 60000,  // 30秒超时
    MAX_RETRIES: 3,       // 最大重试次数
    RETRY_DELAY: 1000     // 重试间隔（毫秒）
};

// 添加重试函数
async function fetchWithRetry(url, options, retries = CONFIG.MAX_RETRIES) {
    try {
        const response = await fetch(url, {
            ...options,
            timeout: CONFIG.CHAT_TIMEOUT,
            headers: {
                ...options.headers,
                'Connect-Timeout-Ms': CONFIG.CHAT_TIMEOUT.toString()
            }
        });
        return response;
    } catch (error) {
        if (retries > 0 && (error.code === 'ETIMEDOUT' || error.type === 'system')) {
            console.log(`Retry attempt ${CONFIG.MAX_RETRIES - retries + 1}, waiting ${CONFIG.RETRY_DELAY}ms...`);
            await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY));
            return fetchWithRetry(url, options, retries - 1);
        }
        throw error;
    }
}
// Modify the chat completions endpoint
app.post('/v1/chat/completions', async (req, res) => {
    try {
        const { 
            messages,
            model,
            temperature = 0.9,
            top_p = 0.9,
            presence_penalty = 1.0,
            frequency_penalty = 1.0,
            stream = false
        } = req.body;
        
        const uid = req.headers.authorization?.replace('Bearer ', '');
        
        if (!uid) {
            return res.status(401).json({ error: 'Authorization token required' });
        }

        // Get JWT using UID
        const jwt = await getJwtFromUid(uid);
        console.log(jwt);
        if (!jwt) {
            return res.status(401).json({ error: 'Failed to get JWT' });
        }

        // 提取非system消息并格式化
        const userMessage = messages
            .map(m => `${m.role}:${m.content}`)
            .join('\n');
        // 提取所有system消息并合并
        const systemMessage = "you are Claude";

        const payload = await createRequestPayload(messages, jwt, {
            systemPrompt: systemMessage,
            temperature,
            top_p,
            presence_penalty,
            frequency_penalty
        });

        const response = await fetchWithRetry('https://server.codeium.com/exa.api_server_pb.ApiServerService/GetChatMessage', {
            method: 'POST',
            headers: {
                'Host': 'server.codeium.com',
                'User-Agent': 'connect-go/1.16.2 (go1.23.2 X:nocoverageredesign)',
                'Accept-Encoding': 'identity',
                'Connect-Accept-Encoding': 'gzip',
                'Connect-Content-Encoding': 'gzip',
                'Connect-Protocol-Version': '1',
                'Content-Type': 'application/connect+proto'
            },
            body: payload
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        if (stream) {
            // Streaming response
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');

            let buffer = Buffer.from([]);
            let fullResponse = '';
            let resultStr = ""
            response.body.on('data', chunk => {
                buffer = Buffer.concat([buffer, chunk]);
                
                while (buffer.length >= 4) {
                    if (buffer.readUInt32LE(0) === 1) {
                        const gzipStart = buffer.indexOf(Buffer.from([0x1f, 0x8b, 0x08]));
                        if (gzipStart !== -1) {
                            const chunk = buffer.slice(gzipStart);
                            try {
                                if (!chunk.includes(Buffer.from([0x03, 0x00]))) {
                                    const decompressed = zlib.gunzipSync(chunk);
                                    
                                    const text = extractText(decompressed);
                                    resultStr = resultStr + text
                                    if (resultStr.includes("user:") || 
                                        resultStr.includes("Human:") || 
                                        resultStr.includes("H:")) {
                                        text = text.split("user:")[0]
                                            .split("Human:")[0]
                                            .split("H:")[0];
                                    } else if (resultStr.endsWith("user") || 
                                            resultStr.endsWith("Human") || 
                                            resultStr.endsWith("H")){
                                        resultStr = text;
                                        continue;
                                    }
                                    if (text) {
                                        fullResponse += text;
                                        const openAIFormat = {
                                            id: `chatcmpl-${uuidv4()}`,
                                            object: 'chat.completion.chunk',
                                            created: Math.floor(Date.now() / 1000),
                                            model: model || 'codeium-default',
                                            choices: [{
                                                delta: { content: text },
                                                index: 0,
                                                finish_reason: null
                                            }]
                                        };
                                        res.write(`data: ${JSON.stringify(openAIFormat)}\n\n`);
                                    }
                                    if (resultStr.includes("user:") || 
                                        resultStr.includes("Human:") || 
                                        resultStr.includes("H:")) {
                                        break;
                                    } 
                                }
                            } catch (e) {
                                console.error('Decompression error:', e);
                            }
                            buffer = buffer.slice(gzipStart + chunk.length);
                        } else {
                            break;
                        }
                    } else {
                        buffer = buffer.slice(1);
                    }
                }
            });

            response.body.on('end', () => {
                res.write('data: [DONE]\n\n');
                res.end();
            });
        } else {
            // Non-streaming response
            let buffer = Buffer.from([]);
            let fullResponse = '';

            for await (const chunk of response.body) {
                buffer = Buffer.concat([buffer, chunk]);
                
                while (buffer.length >= 4) {
                    if (buffer.readUInt32LE(0) === 1) {
                        const gzipStart = buffer.indexOf(Buffer.from([0x1f, 0x8b, 0x08]));
                        if (gzipStart !== -1) {
                            const chunk = buffer.slice(gzipStart);
                            try {
                                if (!chunk.includes(Buffer.from([0x03, 0x00]))) {
                                    const decompressed = zlib.gunzipSync(chunk);
                                    const text = extractText(decompressed);
                                    if (text) {
                                        fullResponse += text;
                                    }
                                }
                            } catch (e) {
                                console.info(buffer)
                                console.error('Decompression error:', e);
                            }
                            buffer = buffer.slice(gzipStart + chunk.length);
                        } else {
                            break;
                        }
                    } else {
                        buffer = buffer.slice(1);
                    }
                }
            }

            // Return complete response in OpenAI format
            const completionResponse = {
                id: `chatcmpl-${uuidv4()}`,
                object: 'chat.completion',
                created: Math.floor(Date.now() / 1000),
                model: model || 'codeium-default',
                choices: [{
                    message: {
                        role: 'assistant',
                        content: fullResponse
                    },
                    index: 0,
                    finish_reason: 'stop'
                }]
            };

            res.json(completionResponse);
        }

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 
