package cn.korostudio.logindemo.service;

import cn.hutool.core.codec.Base62;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.IdUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import cn.korostudio.logindemo.data.User;
import cn.korostudio.logindemo.sql.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController()
@RequestMapping(value = "/api")
public class LoginService {

    protected UserRepository userRepository;
    protected Digester SM3Digester = DigestUtil.digester("sm3");
    protected SymmetricCrypto SM4 = SmUtil.sm4();

    @Autowired
    public void UserHandle(UserRepository userRepository){
        this.userRepository=userRepository;
    }

    @PostMapping("/login")
    public String login(@RequestParam Map<String, Object> params){
        String username,password,passwordSafer;
        username = (String) params.get("username");
        if(username==null)return "{\"status\":\"nullUsername\"}";
        password = (String) params.get("password");
        if(password==null)return "{\"status\":\"nullPassword\"}";
        User user = userRepository.findByUsername(username);
        if(user==null)return "{\"status\":\"noUser\"}";

        passwordSafer = SM3Digester.digestHex(password);

        if (!Objects.equals(user.getPassword(), passwordSafer)){
            return "{\"status\":\"errPassword\"}";
        }

        JSONObject cookieStrJson = JSONUtil.createObj();
        Map<String,String> cookieMap = new HashMap<>();
        cookieMap.put("uuid",user.getUUID());
        cookieMap.put("username",username);
        cookieMap.put("password",passwordSafer);
        cookieStrJson.putAll(cookieMap);

        String cookieBackStr = Base64.encode(cookieStrJson.toString());

        JSONObject cookieBackStrJson = JSONUtil.createObj();
        Map<String,String> cookieBackMap = new HashMap<>();

        cookieBackMap.put("status","ok");
        cookieBackMap.put("value",cookieBackStr);

        cookieBackStrJson.putAll(cookieBackMap);


        return cookieBackStrJson.toString();
    }

    @PostMapping("/check")
    public String check(@RequestParam Map<String, Object> params){
        String json;

        json = (String) params.get("auth");

        JSONObject authJson = JSONUtil.parseObj(Base64.decodeStr(json, CharsetUtil.CHARSET_UTF_8));

        String uuid,username,password;

        uuid = (String) authJson.get("uuid");
        username = (String)authJson.get("username");
        password = (String)authJson.get("password");

        User user = userRepository.findByUUID(uuid);

        if(user==null)return "{\"status\":\"err\"}";
        if(!Objects.equals(user.getUsername(), username))return "{\"status\":\"err\"}";
        if(!Objects.equals(user.getPassword(), password))return "{\"status\":\"err\"}";
        return "{\"status\":\"ok\"}";
    }

    @PostMapping("/register")
    public String register(@RequestParam Map<String, Object> params){
        String username,password,passwordSafer;
        username = (String) params.get("username");
        if(username==null)return "{\"status\":\"errUsername\"}";
        password = (String) params.get("password");
        if(password==null)return "{\"status\":\"errPassword\"}";

        User user = userRepository.findByUsername(username);
        if(user!=null)return "{\"status\":\"hasUser\"}";

        passwordSafer = SM3Digester.digestHex(password);

        User userSave = new User();
        userSave.setUsername(username);
        userSave.setPassword(passwordSafer);
        userSave.setUUID(IdUtil.simpleUUID());

        userRepository.save(userSave);

        return "{\"status\":\"ok\"}";
    }
}
