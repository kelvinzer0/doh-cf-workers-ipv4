// SPDX-License-Identifier: 0BSD
const doh = 'https://security.cloudflare-dns.com/dns-query'
const dohjson = 'https://security.cloudflare-dns.com/dns-query'
const contype = 'application/dns-message'
const jstontype = 'application/dns-json'
const path = ''; // default allow all, must start with '/' if specified, eg. "/dns-query"
const r404 = new Response(null, {status: 404});

// DNS response codes
const DNS_RCODE_NXDOMAIN = 3;

// developers.cloudflare.com/workers/runtime-apis/fetch-event/#syntax-module-worker
export default {
    async fetch(r, env, ctx) {
        return handleRequest(r);
    },
};

async function handleRequest(request) {
    // when res is a Promise<Response>, it reduces billed wall-time
    // blog.cloudflare.com/workers-optimization-reduces-your-bill
    let res = r404;
    const { method, headers, url } = request
    const {searchParams, pathname} = new URL(url)
    
    //Check path
    if (!pathname.startsWith(path)) {
        return r404;
    }

    if (method == 'GET' && searchParams.has('dns')) {
        // Check if this is an AAAA query in base64 encoded DNS message
        const dnsQuery = searchParams.get('dns');
        if (await isAAAAQuery(dnsQuery)) {
            return createNXDomainResponse();
        }
        
        res = fetch(doh + '?dns=' + dnsQuery, {
            method: 'GET',
            headers: {
                'Accept': contype,
            }
        });
    } else if (method === 'POST' && headers.get('content-type') === contype) {
        // Read the request body to check for AAAA queries
        const requestBody = await request.arrayBuffer();
        if (isAAAAQueryBinary(new Uint8Array(requestBody))) {
            return createNXDomainResponse();
        }
        
        res = fetch(doh, {
            method: 'POST',
            headers: {
                'Accept': contype,
                'Content-Type': contype,
            },
            body: requestBody,
        });
    } else if (method === 'GET' && headers.get('Accept') === jstontype) {
        const search = new URL(url).search;
        
        // Check JSON-style queries for AAAA type
        const params = new URLSearchParams(search);
        if (params.get('type') === 'AAAA' || params.get('type') === '28') {
            return new Response(JSON.stringify({
                Status: DNS_RCODE_NXDOMAIN,
                TC: false,
                RD: true,
                RA: true,
                AD: false,
                CD: false,
                Question: [{
                    name: params.get('name') || '',
                    type: 28
                }],
                Answer: []
            }), {
                headers: {
                    'Content-Type': jstontype
                }
            });
        }
        
        res = fetch(dohjson + search, {
            method: 'GET',
            headers: {
                'Accept': jstontype,
            }
        });
    }
    return res;
}

// Function to check if base64 encoded DNS query is for AAAA record
async function isAAAAQuery(base64Query) {
    try {
        // Decode base64 (URL-safe)
        const binaryString = atob(base64Query.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        
        return isAAAAQueryBinary(bytes);
    } catch (e) {
        return false;
    }
}

// Function to check if binary DNS query is for AAAA record
function isAAAAQueryBinary(bytes) {
    try {
        // DNS header is 12 bytes, question starts at byte 12
        if (bytes.length < 16) return false;
        
        // Skip DNS header (12 bytes) and domain name
        let offset = 12;
        
        // Skip domain name (ends with 0x00)
        while (offset < bytes.length && bytes[offset] !== 0) {
            const labelLength = bytes[offset];
            if (labelLength > 63) break; // Invalid label length
            offset += labelLength + 1;
        }
        offset++; // Skip the null terminator
        
        // Check if we have enough bytes for QTYPE (2 bytes)
        if (offset + 2 > bytes.length) return false;
        
        // Read QTYPE (2 bytes, big endian)
        const qtype = (bytes[offset] << 8) | bytes[offset + 1];
        
        // AAAA record type is 28
        return qtype === 28;
    } catch (e) {
        return false;
    }
}

// Create NXDOMAIN response for blocked AAAA queries
function createNXDomainResponse() {
    // Create minimal DNS response with NXDOMAIN
    const response = new Uint8Array([
        0x00, 0x00, // Transaction ID (will be overwritten)
        0x81, 0x83, // Flags: Response, NXDOMAIN
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Original question will be echoed back
    ]);
    
    return new Response(response, {
        headers: {
            'Content-Type': contype
        }
    });
}
