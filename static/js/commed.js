 (function(){
    var showMune=false;
    $("#showPhoneMune").on("click",function(){
        if(showMune==false){
            $("#PhoneMune,.rootwarp,.navbar-fixed-top").addClass("show");

           showMune=true;
        }else{
            $("#PhoneMune,.rootwarp,.navbar-fixed-top").removeClass("show");
             showMune=false
        }

    })
})()