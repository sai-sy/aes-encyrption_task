#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
//the encryption/decryption function
int do_crypt(const unsigned char* ciphertext, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext, int do_crypt)
{

    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx,EVP_aes_128_cbc(), NULL, key, iv, do_crypt);

    EVP_CipherUpdate(ctx, plaintext, &inlen, ciphertext, 32);

    outlen = inlen;
    EVP_CipherFinal(ctx, plaintext+inlen, &inlen);
    outlen += inlen;
    plaintext[outlen] = '\0';

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// add padding to the possible key
void create_key(char* word, char* key){
    int len = strlen(word);
    int i;

    for (i = 0; i < len; i++){
        key[i] = word[i];
    }

    for (int j = i; j < 16; j++){
        key[j] = '#';
    }
}

int main(){
  // set the known values
    const char* plaintext_expected =  "This is a top secret.";
    unsigned char ciphertext[] = {0x76, 0x4a, 0xa2, 0x6b, 0x55, 0xa4, 0xda, 0x65, 
                 0x4d, 0xf6, 0xb1, 0x9e, 0x4b, 0xce, 0x00, 0xf4,
                 0xed, 0x05, 0xe0, 0x93, 0x46, 0xfb, 0x0e, 0x76, 
                 0x25, 0x83, 0xcb, 0x7d, 0xa2, 0xac, 0x93, 0xa2};

    unsigned char iv[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};

    unsigned char key[16];

    unsigned char plaintext[128];

    FILE* wordsfile = fopen("words.txt", "r");

    if (!wordsfile){
        printf("error opening the words file\nExiting...\n");
        return 1;
    }

    char word[17];

    printf("Running...\n");
  //iterate over every word
    while (fgets(word, sizeof(word), wordsfile)) {
        word[strcspn(word, "\n")] = 0;
    //add padding
        create_key(word, key);
    //decrypt using the possible key
        do_crypt(ciphertext, key, iv, plaintext, 0);
    // check if the decrypted plaintext is the same as the original
        if (strcmp((char *) plaintext, plaintext_expected) == 0){
            //if so print the found key and return
            printf("Key found: %s\n", word);
            fclose(wordsfile);
            return 0;
        }
    //if not then continue iterating
    }
    printf("No key found\n");

}
