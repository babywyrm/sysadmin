package com.linhnguyen.demo.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

public class RedirectController {
	
	/**
	 * Redirect to internal url
	 */
	@RequestMapping("/")
	public String home(RedirectAttributes attributes) {
		
		//Pass data to redirect page
		attributes.addFlashAttribute("message", "This is message!");
		//Redirect to request mapping "target" 
		return "redirect:/target";
	}
	
	@RequestMapping("/target")
	public String redirectTarget(@ModelAttribute String message, Model model) {
		
		//Pass data to redirect page
		model.addAttribute("message", message);
		return "targetPage";
	}
	
	/**
	 * Redirect to external URL
	 */
	@RequestMapping("/redirect")
	public RedirectView redirectWithRedirectView(){
		
		RedirectView redirectView = new RedirectView();
		redirectView.setUrl("https://www.google.com.vn");
		return redirectView;
	}

}
