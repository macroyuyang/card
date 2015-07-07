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


/*
设置cookie
*/

function setCookie(name, value, iDay){   
    var oDate=new Date();   
    oDate.setDate(oDate.getDate()+iDay);       
    document.cookie=name+'='+value+';expires='+oDate;
}



 /* 获取cookie */  
function getCookie(name){
    
    var arr=document.cookie.split('; ');  
    
    for(var i=0;i<arr.length;i++)    {
        /* 将cookie名称和值拆分进行判断 */       
        var arr2=arr[i].split('=');               
        if(arr2[0]==name){           
            return arr2[1];       
        }   
    }       
    return '';
}
/* -1 天后过期即删除 */ 
function removeCookie(name){   
      
    setCookie(name, 1, -1);
}

/*读取cookie*/
jQuery("#cartNum").html(getCookie('cartnum'));

if(parseInt(jQuery("#cartNum").html())>0){
     jQuery("#cartNum").fadeIn();
}


/*显示隐藏购物车*/

$("#cartend").click(function(){
    if($(".cart-widget").is(":hidden")){
        $(".cart-widget").fadeIn();
    }else{
        $(".cart-widget").fadeOut();
    }
});



$("header .login").bind("click",function(){
    var xl=$(this).find(".ullit");
    if(xl.is(":hidden")){
        xl.slideDown();
        
    }else{
        xl.slideUp();
    }
})








