#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>

/**
 * @brief The SHA256 class computes the SHA-256 hash of input data.
 */
class SHA256 {
public:
    /**
     * @brief Compute the SHA-256 hash of the given data.
     * @param data The input data to be hashed.
     * @return The SHA-256 hash as a hexadecimal string.
     */
    static std::string hash(const std::string& data) {
        SHA256 sha;
        sha.update(data);
        return sha.finalize();
    }

    // Constants used in the SHA-256 algorithm
private:
    static constexpr unsigned int k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initial hash values
    unsigned int h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };


    std::vector<unsigned char> data; // Data buffer
     unsigned int w[64]; // Message schedule array


     /**
      * @brief Perform a right rotation operation.
      * @param x The input value.
      * @param n The number of bits to rotate.
      * @return The result of the rotation operation.
      */
     static inline unsigned int rotr(unsigned int x, unsigned int n) {
         return (x >> n) | (x << (32 - n));
     }

    static inline unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
        return (x & y) ^ (~x & z);
    }

    static inline unsigned int maj(unsigned int x, unsigned int y, unsigned int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline unsigned int sigma0(unsigned int x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline unsigned int sigma1(unsigned int x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline unsigned int omega0(unsigned int x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline unsigned int omega1(unsigned int x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    /**
        * @brief Perform the SHA-256 transformation on a 512-bit chunk of data.
        */
       void transform() {
           // Message schedule expansion
           for (unsigned int t = 16; t < 64; ++t) {
               w[t] = omega1(w[t - 2]) + w[t - 7] + omega0(w[t - 15]) + w[t - 16];
           }

           // Initialize hash value for this chunk
        unsigned int a = h[0];
        unsigned int b = h[1];
        unsigned int c = h[2];
        unsigned int d = h[3];
        unsigned int e = h[4];
        unsigned int f = h[5];
        unsigned int g = h[6];
        unsigned int h0 = h[7];

        // Main loop of the SHA-256 algorithm
        for (unsigned int t = 0; t < 64; ++t) {
            unsigned int T1 = h0 + sigma1(e) + ch(e, f, g) + k[t] + w[t];
            unsigned int T2 = sigma0(a) + maj(a, b, c);
            h0 = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Update hash values
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h0;
    }

       /**
            * @brief Update the hash computation with additional data.
            * @param msg The input message.
            */

    void update(const std::string& msg) {
        // Append the input message bytes to the data vector
        for (char c : msg) {
            data.push_back(static_cast<unsigned char>(c));
        }

        // Process the data in 512-bit (64-byte) chunks
        while (data.size() >= 64) {
            // Copy chunk into first 16 words w[0..15] of the message schedule array
            for (int j = 0; j < 16; ++j) {
                w[j] = (data[j * 4] << 24) |
                       (data[j * 4 + 1] << 16) |
                       (data[j * 4 + 2] << 8) |
                       (data[j * 4 + 3]);
            }

            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            for (int j = 16; j < 64; ++j) {
                unsigned int s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >> 3);
                unsigned int s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >> 10);
                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
            }

            // Perform the SHA-256 transformation
            transform();

            // Remove the processed bytes from the data vector
            data.erase(data.begin(), data.begin() + 64);
        }
    }


    /**
        * @brief Finalize the hash computation and generate the hash value.
        * @return The SHA-256 hash as a hexadecimal string.
        */
    std::string finalize() {
        // Padding: append a bit '1' followed by '0' bits, leaving 64 bits at the end for the length
        size_t originalLength = data.size();
        size_t padLength = 64 - (originalLength + 8) % 64;
        data.push_back(0x80); // Append the bit '1'
        padLength -= 1;

        // Append '0' bits
        for (size_t i = 0; i < padLength; ++i) {
            data.push_back(0x00);
        }

        // Append the length of the original message in bits as a 64-bit big-endian integer
        uint64_t bitLength = static_cast<uint64_t>(originalLength) * 8;
        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<unsigned char>((bitLength >> (8 * i)) & 0xff));
        }

        // Process the final padded message
        for (size_t i = 0; i < data.size() / 64; ++i) {
            for (int j = 0; j < 16; ++j) {
                w[j] = (data[i * 64 + j * 4] << 24) |
                       (data[i * 64 + j * 4 + 1] << 16) |
                       (data[i * 64 + j * 4 + 2] << 8) |
                       (data[i * 64 + j * 4 + 3]);
            }
            transform();
        }

        // Convert the hash components to a hex string
        std::stringstream ss;
          ss << "0x ";
          for (int i = 0; i < 8; i++) {
              ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
              if (i < 7)
                  ss << "";
          }
          return ss.str();
      }
};

/**
 * @brief Main function to demonstrate the usage of the SHA256 class.
 * @return Exit code.
 */

	int main() {
		std::string input;
		std::cout << "Enter a string to hash with SHA256: ";
		std::getline(std::cin, input);

		std::string output = SHA256::hash(input);
		std::cout << "SHA256(\"" << input << "\") = " << output << std::endl;

		return 0;
	}

