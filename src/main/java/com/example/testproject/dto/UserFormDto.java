//package com.example.testproject.dto;
//
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;
//import jakarta.validation.constraints.NotEmpty;
//import lombok.Getter;
//import lombok.Setter;
//import org.hibernate.validator.constraints.Length;
//
//@Getter
//@Setter
//public class UserFormDto {
//    @NotBlank(message="아이디는 필수 입력값 입니다.")
//    @Length(min=4, max=16, message="아이디는 4자이상, 16자 이하로 입력해주세요.")
//    private String users_id;
//
//    @NotEmpty(message="비밀번호는 필수 입력값입니다.")
//    @Length(min=8, max=16, message="비밀번호는 8자이상, 16자 이하로 입력해주세요.")
//    private String pw;
//    private String pw_check;
//
//    @NotEmpty(message="이름은 필수 입력값입니다.")
//    private String name;
//
//    @NotEmpty(message="전화번호는 필수 입력값입니다.")
//    private String phone;
//
//    @NotEmpty(message="이메일은 필수 입력값입니다.")
//    @Email(message="이메일 형식으로 입력해주세요.")
//    private String email;
//}


package com.example.testproject.dto;

import com.example.testproject.entity.Role;
import com.example.testproject.entity.Users;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;


@ToString
@AllArgsConstructor
@Getter
@Setter
public class UserFormDto {

    private Long id;
    private String userId;

//    @NotEmpty(message="비밀번호는 필수 입력값입니다.")
//    @Length(min=8, max=16, message="비밀번호는 8자이상, 16자 이하로 입력해주세요.")
    private String pw;


    private String pwCheck;

//    @NotEmpty(message="이름은 필수 입력값입니다.")
    private String name;

//    @NotEmpty(message="전화번호는 필수 입력값입니다.")
    private String phone;

//    @NotEmpty(message="이메일은 필수 입력값입니다.")
//    @Email(message="이메일 형식으로 입력해주세요.")
    private String email;

    private Role role;
        public Users toEntity() {
        return new Users(id, userId, pw, pwCheck, name, phone, email, role);
    }
}