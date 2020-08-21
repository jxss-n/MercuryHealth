$( document ).ready(function() {

  $(".nav-link").on("click", function(){
    console.log("im being called!");
     $(".nav-item").find(".active").removeClass("active");
     $(this).addClass("active");
  });

});
