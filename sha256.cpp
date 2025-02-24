#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

class SHA256
{
private:
    // Initial hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // Utility functions
    uint32_t rightRotate(uint32_t value, unsigned int count)
    {
        return (value >> count) | (value << (32 - count));
    }

    uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (~x & z);
    }

    uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    uint32_t ep0(uint32_t x)
    {
        return rightRotate(x, 2) ^ rightRotate(x, 13) ^ rightRotate(x, 22);
    }

    uint32_t ep1(uint32_t x)
    {
        return rightRotate(x, 6) ^ rightRotate(x, 11) ^ rightRotate(x, 25);
    }

    uint32_t sig0(uint32_t x)
    {
        return rightRotate(x, 7) ^ rightRotate(x, 18) ^ (x >> 3);
    }

    uint32_t sig1(uint32_t x)
    {
        return rightRotate(x, 17) ^ rightRotate(x, 19) ^ (x >> 10);
    }

public:
    std::string hash(const std::string &message)
    {
        // Pre-processing
        std::vector<uint8_t> padded;
        uint64_t ml = message.length() * 8; // Message length in bits

        // Copy message to padded vector
        for (char c : message)
        {
            padded.push_back(static_cast<uint8_t>(c));
        }

        // Append the bit '1' to the message
        padded.push_back(0x80);

        // Append zeros
        while ((padded.size() * 8 + 64) % 512 != 0)
        {
            padded.push_back(0x00);
        }

        // Append message length as 64-bit big-endian integer
        for (int i = 7; i >= 0; --i)
        {
            padded.push_back(static_cast<uint8_t>((ml >> (i * 8)) & 0xFF));
        }

        // Process the message in successive 512-bit chunks
        for (size_t i = 0; i < padded.size(); i += 64)
        {
            uint32_t w[64] = {0};

            // Create the first 16 words
            for (int j = 0; j < 16; ++j)
            {
                w[j] = (padded[i + j * 4] << 24) |
                       (padded[i + j * 4 + 1] << 16) |
                       (padded[i + j * 4 + 2] << 8) |
                       (padded[i + j * 4 + 3]);
            }

            // Extend the first 16 words into the remaining 48 words
            for (int j = 16; j < 64; ++j)
            {
                w[j] = w[j - 16] + sig0(w[j - 15]) + w[j - 7] + sig1(w[j - 2]);
            }

            // Initialize working variables
            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;

            // Main loop
            for (int j = 0; j < 64; ++j)
            {
                uint32_t temp1 = h + ep1(e) + ch(e, f, g) + k[j] + w[j];
                uint32_t temp2 = ep0(a) + maj(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Add compressed chunk to current hash value
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        // Produce the final hash value (big-endian)
        std::stringstream ss;
        ss << std::hex << std::setfill('0')
           << std::setw(8) << h0
           << std::setw(8) << h1
           << std::setw(8) << h2
           << std::setw(8) << h3
           << std::setw(8) << h4
           << std::setw(8) << h5
           << std::setw(8) << h6
           << std::setw(8) << h7;
        return ss.str();
    }
};

// Function to fetch content from URL using WinHTTP
std::string fetchUrlContent(const std::string &url)
{
    std::string result;
    DWORD dataSize = 0;
    DWORD downloadedSize = 0;
    LPSTR outBuffer;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL,
              hConnect = NULL,
              hRequest = NULL;

    // Initialize WinHTTP
    hSession = WinHttpOpen(L"SHA256 Book of Mark/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession)
    {
        // Convert URL to wide string
        std::wstring wideUrl(url.begin(), url.end());

        // Crack the URL
        URL_COMPONENTS urlComp;
        wchar_t hostName[256];
        wchar_t urlPath[1024];

        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = sizeof(hostName) / sizeof(hostName[0]);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(urlPath[0]);

        WinHttpCrackUrl(wideUrl.c_str(), wideUrl.length(), 0, &urlComp);

        // Connect to server
        hConnect = WinHttpConnect(hSession, urlComp.lpszHostName,
                                  urlComp.nPort, 0);

        if (hConnect)
        {
            // Create request
            hRequest = WinHttpOpenRequest(hConnect, L"GET",
                                          urlComp.lpszUrlPath,
                                          NULL, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);

            if (hRequest)
            {
                // Send request
                bResults = WinHttpSendRequest(hRequest,
                                              WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

                if (bResults)
                {
                    bResults = WinHttpReceiveResponse(hRequest, NULL);
                }

                // Keep checking for data until there is nothing left.
                if (bResults)
                {
                    do
                    {
                        dataSize = 0;
                        WinHttpQueryDataAvailable(hRequest, &dataSize);

                        // Allocate space for the buffer.
                        outBuffer = new char[dataSize + 1];
                        if (outBuffer)
                        {
                            // Read the data.
                            ZeroMemory(outBuffer, dataSize + 1);

                            if (WinHttpReadData(hRequest, (LPVOID)outBuffer,
                                                dataSize, &downloadedSize))
                            {
                                result.append(outBuffer, downloadedSize);
                            }

                            delete[] outBuffer;
                        }
                    } while (dataSize > 0);
                }
            }
        }
    }

    // Close any open handles.
    if (hRequest)
        WinHttpCloseHandle(hRequest);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hSession)
        WinHttpCloseHandle(hSession);

    return result;
}

int main()
{
    // Fetch the Book of Mark text from the website
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    std::string bookOfMark = fetchUrlContent(url);

    if (bookOfMark.empty())
    {
        std::cerr << "Failed to fetch content from URL" << std::endl;
        return 1;
    }

    // Create SHA256 hasher and compute hash
    SHA256 sha256;
    std::string hash = sha256.hash(bookOfMark);

    std::cout << "SHA-256 hash of the Book of Mark: " << hash << std::endl;
    return 0;
}
