
/**
 * 网站公用组件库
 * @param  {[type]} $ [jquery]
 * @return {[type]}   [description]
 */
(function($){

    /**
     * [scrollEv 头部滚动样式]
     * @param  {[type]} opt [classes 控制添加与删除的样式]
     * @return {[type]}     [首页导航滚动样式]
     */
    $.fn.scrollEv=function(opt){
        var def={
            classes:"index-head",
            range:60
        }
        obj=$.extend(opt,def);
        var _this=$(this);
       $(window).scroll(function(){
            var top=$(window).scrollTop();
            if(top>obj.range){
                _this.removeClass(obj.classes);
            }else if(top<obj.range){
                _this.addClass(obj.classes);
            }
       })
    }

})(jQuery);