let displayThanks = function() {
  alert("inside display THANKS");
    $("#signupBeta").css("display", "none");
    $("#confirmBeta").css("display","block");
    setTimeout(function(){
        console.log('timing out');
    }, 2000);
}
