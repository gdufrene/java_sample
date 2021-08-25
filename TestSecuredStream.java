// package cipher;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class TestSecuredStream {
    
    SecretKey key;
    IvParameterSpec iv;
    
    @Test
    public void testStream() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        String encodedKey = "55UHQMBUC4a6GXefgieWOA==";
        String encodedIv = "YVqbds592GmyQ4XUEUyDqA==";
        
        key = new SecretKeySpec( Base64.getDecoder().decode(encodedKey), "AES" );
        iv = new IvParameterSpec( Base64.getDecoder().decode(encodedIv) );
        
        OutputStream out = OutputStreamBuilder.from(bos)
            .base64()
            .cipherBuilder()
                .withGeneratedKey( k -> key = k )
                .withRandomIv( iv -> TestSecuredStream.this.iv = iv )
//                    .withKey(key)
//                    .withIv(iv)
                .and()
            .build();
        out.write( "Hello world !!!".getBytes(Charset.forName("UTF-8")) );
        out.close();
        
        byte[] encrypted = bos.toByteArray();
        // System.out.println( Base64.getEncoder().encodeToString(encrypted) );
        System.out.println( new String(encrypted) );
        
        BufferedReader in = InputStreamBuilder.from( new ByteArrayInputStream(encrypted) )
            .base64()
            .uncipherBuilder()
                .withKey(key)
                .withIv(iv)
                .and()
            .buffered();
        
        System.out.println( in.readLine() );
        
    }
    
    @Test
    public void testObjectMapper() throws Exception {
        
        String encodedKey = "55UHQMBUC4a6GXefgieWOA==";
        String encodedIv = "YVqbds592GmyQ4XUEUyDqA==";
        key = new SecretKeySpec( Base64.getDecoder().decode(encodedKey), "AES" );
        iv = new IvParameterSpec( Base64.getDecoder().decode(encodedIv) );
        
        IOBuilder builder = new IOBuilder()
            .withIv(iv)
            .withKey(key);
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        Pojo pojo = new Pojo();
        pojo.setName("Guillaume Dufrêne");
        pojo.setNumber(3.141592);
        pojo.setDatetime(LocalDateTime.now());
        for (int i = 0; i < 100; i++) {            
            pojo.getElements().add("Element " + i);
        }
        
        ObjectMapper mapper = new ObjectMapper();
        
        mapper.registerModule(new JavaTimeModule());
        
        mapper.writeValue(builder.outputStream(bos), pojo);
        
        byte[] encrypted = bos.toByteArray();
        System.out.println( new String(encrypted) );
        System.out.println( "Data size: " + encrypted.length );
        
        
        Reader reader = builder.reader(new ByteArrayInputStream(encrypted));
        Pojo decrypted = mapper.readValue(reader, Pojo.class);
        
        String decryptedString = decrypted.toString();
        System.out.println( decryptedString );
        System.out.println( "Decrypted data size: " + decryptedString.length() );
        

        
    }

}


class IOBuilder {
    
    SecretKey key;
    IvParameterSpec iv;
    
    public IOBuilder withKey(SecretKey key) {
        this.key = key;
        return this;
    }
    
    public IOBuilder withIv(IvParameterSpec iv) {
        this.iv = iv;
        return this;
    }
    
    OutputStream outputStream(OutputStream from) { 
        return OutputStreamBuilder.from(from)
            .base64()
            .cipherBuilder()
                .withKey(key)
                .withIv(iv)
                .and()
            .gzip()
            .build();
    }
    
    BufferedReader reader(InputStream from) {
        return InputStreamBuilder.from( from )
            .base64()
            .uncipherBuilder()
                .withKey(key)
                .withIv(iv)
                .and()
            .gzip()
            .buffered();
    }
}

class InputStreamBuilder {
    InputStream in;
    
    public static InputStreamBuilder from(InputStream in) {
        InputStreamBuilder res = new InputStreamBuilder();
        res.in = in;
        return res;
    }
    
    public CipherBuilder<InputStreamBuilder> uncipherBuilder() {
        return new CipherBuilder<>(this)
            .withDecryptMode()
            .whenBuilt(this::withCipher);
    }
    
    public BufferedReader buffered() {
        return new BufferedReader( new InputStreamReader(in, Charset.forName("UTF-8")) );
    }
    
    InputStream build() {
        return in;
    }
    
    public InputStreamBuilder withCipher(Cipher cipher) {
        in = new CipherInputStream(in, cipher);
        return this;
    }
    
    public InputStreamBuilder base64() {
        in = Base64.getDecoder().wrap(in);
        return this;
    }
    
    public InputStreamBuilder gzip() {
        try {
            in = new GZIPInputStream(in);
        } catch (IOException e) {
            throw new RuntimeException("Unable to create gzip input", e);
        }
        return this;
    }
}


class OutputStreamBuilder {
    OutputStream out;
    
    public static OutputStreamBuilder from(OutputStream out) {
        OutputStreamBuilder builder = new OutputStreamBuilder();
        builder.out = out;
        return builder;
    }
    
    public OutputStreamBuilder base64() {
        out = Base64.getEncoder().wrap(out);
        return this;
    }
    
    public OutputStreamBuilder gzip() {
        try {
            out = new GZIPOutputStream(out);
        } catch (IOException e) {
            throw new RuntimeException("Unable to create gzip output", e);
        }
        return this;
    }
    
    public CipherBuilder<OutputStreamBuilder> cipherBuilder() {
        return new CipherBuilder<>(this)
            .whenBuilt(this::withCipher);
    }
    
    public OutputStreamBuilder withCipher(Cipher cipher) {
        out = new CipherOutputStream(out, cipher);
        return this;
    }
    
    public OutputStream build() {
        return out;
    }
}

class CipherBuilder<Parent> {
    int keySize = 128;
    String cipherName = "AES/CBC/PKCS5Padding";
    SecretKey key;
    IvParameterSpec iv;
    int opMode = Cipher.ENCRYPT_MODE;
    
    Parent parent;
    Consumer<Cipher> whenBuilt;
    
    CipherBuilder(Parent p) {
        this.parent = p;
    }
    
    Parent and() {
        try {
            final Cipher res = Cipher.getInstance(cipherName);
            SecretKey secretKey = Optional
                .ofNullable(key)
                .orElseGet(this::generateNewKey);
            IvParameterSpec ivParameterSpec = Optional
                .ofNullable(iv)
                .orElseGet(this::generateNewIv);
            res.init(opMode, secretKey,ivParameterSpec);
            Optional.ofNullable(whenBuilt)
                .ifPresent( setter -> setter.accept(res) );
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException("Unable to create cipher", e);
        }
        return parent;
    }
    
    public CipherBuilder<Parent> withEncryptMode() {
        opMode = Cipher.ENCRYPT_MODE;
        return this;
    }
    
    public CipherBuilder<Parent> withDecryptMode() {
        opMode = Cipher.DECRYPT_MODE;
        return this;
    }

    public CipherBuilder<Parent> withKey(SecretKey key) {
        this.key = key;
        return this;
    }
    
    public CipherBuilder<Parent> withEncodedKey(String key) {
        this.key = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        return this;
    }
    
    
    public CipherBuilder<Parent> withIv(IvParameterSpec iv) {
        this.iv = iv;
        return this;
    }
    
    public CipherBuilder<Parent> withEncodedIv(String iv) {
        this.iv = new IvParameterSpec(Base64.getDecoder().decode(iv));
        return this;
    }

    public CipherBuilder<Parent> whenBuilt(Consumer<Cipher> whenBuilt) {
        this.whenBuilt = whenBuilt;
        return this;
    }
    
    CipherBuilder<Parent> withGeneratedKey(Consumer<SecretKey> setter) {
        key = generateNewKey();
        System.out.println("Generated key : " + Base64.getEncoder().encodeToString(key.getEncoded()) );
        setter.accept(key);
        return this;
    }
    
    CipherBuilder<Parent> withRandomIv(Consumer<IvParameterSpec> setter) {
        iv = generateNewIv();
        System.out.println("Generated Iv : " + Base64.getEncoder().encodeToString(iv.getIV()) );
        setter.accept(iv);
        return this;
    }
    
    SecretKey generateNewKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keySize);
            SecretKey key = keyGenerator.generateKey();
            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to generate a secret key", e);
        }
    }
    
    public IvParameterSpec generateNewIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
