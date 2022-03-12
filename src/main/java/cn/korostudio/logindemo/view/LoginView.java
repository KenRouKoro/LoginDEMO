package cn.korostudio.logindemo.view;

import cn.hutool.core.codec.Base62;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.digest.DigestUtil;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import cn.korostudio.logindemo.data.User;
import cn.korostudio.logindemo.sql.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;
import java.util.Objects;

@Controller
public class LoginView {

    protected UserRepository userRepository;
    protected Digester SM3Digester = DigestUtil.digester("sm3");
    protected SymmetricCrypto SM4 = SmUtil.sm4();

    @Autowired
    public void UserHandle(UserRepository userRepository){
        this.userRepository=userRepository;
    }

    @RequestMapping("/")
    public String index(ModelMap modelMap, @CookieValue(value = "auth",defaultValue = "null")String auth){
        if (Objects.equals(auth, "null")) return "index";
        String checkStr = check(auth);
        if (Objects.equals(checkStr, "false"))return "index";
        JSONObject authJson = JSONUtil.parseObj(checkStr);
        String uuid,username,password;

        uuid = (String) authJson.get("uuid");
        username = (String)authJson.get("username");
        password = (String)authJson.get("password");

        modelMap.put("uuid",uuid);
        modelMap.put("username",username);
        modelMap.put("password",password);

        return "auth";

    }
    public String check(String auth){
        JSONObject authJson = JSONUtil.parseObj(Base64.decodeStr(auth, CharsetUtil.CHARSET_UTF_8));
        String uuid,username,password;

        uuid = (String) authJson.get("uuid");
        username = (String)authJson.get("username");
        password = (String)authJson.get("password");

        User user = userRepository.findByUUID(uuid);

        if(user==null) return "false";
        if(!Objects.equals(user.getUsername(), username))return "false";
        if(!Objects.equals(user.getPassword(), password))return "false";
        return authJson.toString();
    }


}
