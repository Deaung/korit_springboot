package com.korit.authstudy.init;

import com.korit.authstudy.domain.entity.User;
import jakarta.persistence.Id;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.function.Consumer;

@RequiredArgsConstructor
class OptionalStudy<T> {
    private final T present;


    public void ifPresentOrElse(Consumer<T> action, Runnable runnable) {
        if (present != null){
            action.accept(present);
        } else {
            runnable.run();
        }
    }
}

@Component
public class Lambda implements CommandLineRunner {

    @Override
    public void run(String... args) throws Exception {
        User user = User.builder()
                .id(100)
                .username("test")
                .password("1234")
                .build();
        OptionalStudy<User> userOptionalStudy = new OptionalStudy<>(user);

        Consumer<User> consumer = new Consumer<User>() {
            @Override
            public void accept(User user) {
                System.out.println("user 객체 찾음 :" + user);
            }
        };
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                System.out.println("user 객체 못찾아서 다른작업 실행");
            }
        };
        userOptionalStudy.ifPresentOrElse(consumer,runnable);

        Consumer<User> userConsumer = (u) -> {
            System.out.println("객체 찾음 :" + u);
        };
        Runnable runnable1 = () ->{
            System.out.println("객체 못찾음");
        };

        userOptionalStudy.ifPresentOrElse(userConsumer,runnable1);

        userOptionalStudy.ifPresentOrElse((us)->{}, () -> {});
    }

}
