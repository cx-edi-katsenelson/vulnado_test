package com.scalesec.vulnado;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CowController {
  private Cowsay cowsay = new Cowsay();

  @GetMapping("/cowsay")
  public String cowsay(@RequestParam String input) {
    return cowsay.run(input);
  }
}
