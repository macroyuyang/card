insert into cardtype(id, name, description) values(1, '实体卡', '线下使用');
insert into cardtype(id, name, description) values(2, '电子卡', '线上使用');

insert into cardcategory(id, name, description) values(1, '购物卡', '');
insert into cardcategory(id, name, description) values(2, '电影券', '');
insert into cardcategory(id, name, description) values(3, '娱乐卡', '');
insert into cardcategory(id, name, description) values(4, '代金券', '');
insert into cardcategory(id, name, description) values(5, '餐饮卡', '');

insert into pic values(1, '/static/img/temp/k1.jpg', '');

insert into merchant values(1, '家乐福', '400-820-0889', 'www.carrefour.com.cn');
insert into merchant values(2, '家乐福', '400-820-0889', 'www.carrefour.com.cn');

insert into card values(1, 1, 1, '大甩卖', 100, '家乐福购物卡100元','jialefu', 1,1); 
insert into card values(2, 1, 1, '大甩卖', 300, '家乐福购物卡300元','jialefu', 1,1); 
insert into card values(3, 1, 1, '大甩卖', 400, '家乐福购物卡400元','jialefu', 1,1); 
insert into card values(4, 1, 1, '大甩卖', 500, '家乐福购物卡500元','jialefu', 1,1); 
insert into card values(5, 1, 1, '大甩卖', 600, '家乐福购物卡600元','jialefu', 1,1); 
insert into card values(6, 1, 1, '大甩卖', 700, '家乐福购物卡700元','jialefu', 1,1); 
insert into card values(7, 1, 1, '大甩卖', 800, '家乐福购物卡800元','jialefu', 1,1); 
insert into card values(8, 1, 1, '大甩卖', 900, '家乐福购物卡900元','jialefu', 1,1); 

insert into account values(1, 'xxx@gmail.com', 'xxx', 'LIV', 'YangYu', '13810772922', '123456', 'VIP');

insert into sellitem values(1, 1, 95, 100, 1, 'NW', '2015-01-01', '2016-01-01', '', '', '', '');
insert into sellitem values(2, 1, 90, 100, 1, 'NW', '2015-02-01', '2016-02-01', '', '', '', '');
insert into sellitem values(3, 1, 60, 70, 1, 'NW', '2015-03-01', '2016-03-01', '', '', '', '');
insert into sellitem values(4, 1, 70, 80, 1, 'NW', '2015-04-01', '2016-04-01', '', '', '', '');

insert into sellitem values(5, 2, 95, 100, 1, 'NW', '2015-01-01', '2016-01-01', '', '', '', '');
insert into sellitem values(6, 2, 90, 100, 1, 'NW', '2015-02-01', '2016-02-01', '', '', '', '');
insert into sellitem values(7, 2, 60, 70, 1, 'NW', '2015-03-01', '2016-03-01', '', '', '', '');
insert into sellitem values(8, 2, 70, 80, 1, 'NW', '2015-04-01', '2016-04-01', '', '', '', '');

insert into sellitem values(9, 3, 95, 100, 1, 'NW', '2015-01-01', '2016-01-01', '', '', '', '');
insert into sellitem values(10, 3, 90, 100, 1, 'NW', '2015-02-01', '2016-02-01', '', '', '', '');
insert into sellitem values(11, 3, 60, 70, 1, 'NW', '2015-03-01', '2016-03-01', '', '', '', '');
insert into sellitem values(12, 4, 70, 80, 1, 'NW', '2015-04-01', '2016-04-01', '', '', '', '');
insert into sellitem values(13, 5, 70, 80, 1, 'NW', '2015-05-01', '2016-05-01', '', '', '', '');
insert into sellitem values(14, 6, 70, 80, 1, 'NW', '2015-06-01', '2016-06-01', '', '', '', '');
insert into sellitem values(15, 7, 70, 80, 1, 'NW', '2015-07-01', '2016-07-01', '', '', '', '');
insert into sellitem values(16, 7, 70, 80, 1, 'NW', '2015-08-01', '2016-08-01', '', '', '', '');
insert into sellitem values(17, 7, 70, 80, 1, 'NW', '2015-09-01', '2016-09-01', '', '', '', '');
insert into sellitem values(18, 8, 70, 80, 1, 'NW', '2015-10-01', '2016-10-01', '', '', '', '');
