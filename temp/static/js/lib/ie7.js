/* To avoid CSS expressions while still supporting IE 7 and IE 6, use this script */
/* The script tag referencing this file must be placed before the ending body tag. */

/* Use conditional comments in order to target IE 7 and older:
	<!--[if lt IE 8]><!-->
	<script src="ie7/ie7.js"></script>
	<!--<![endif]-->
*/

(function() {
	function addIcon(el, entity) {
		var html = el.innerHTML;
		el.innerHTML = '<span style="font-family: \'fontIco\'">' + entity + '</span>' + html;
	}
	var icons = {
		'ico_home': '&#xe900;',
		'ico_news': '&#xe904;',
		'ico_image': '&#xe90d;',
		'ico_bullhorn': '&#xe91a;',
		'ico_connection': '&#xe91b;',
		'ico_profile': '&#xe923;',
		'ico_cart': '&#xe93a;',
		'ico_credit-card': '&#xe93f;',
		'ico_address-book': '&#xe944;',
		'ico_alarm': '&#xe950;',
		'ico_bell': '&#xe951;',
		'ico_calendar': '&#xe953;',
		'ico_keyboard': '&#xe955;',
		'ico_redo2': '&#xe968;',
		'ico_forward': '&#xe969;',
		'ico_reply': '&#xe96a;',
		'ico_bubbles': '&#xe96c;',
		'ico_bubbles2': '&#xe96d;',
		'ico_bubbles4': '&#xe970;',
		'ico_users': '&#xe972;',
		'ico_spinner9': '&#xe982;',
		'ico_spinner10': '&#xe983;',
		'ico_gift': '&#xe99f;',
		'ico_bin': '&#xe9ac;',
		'ico_menu': '&#xe9bd;',
		'ico_warning': '&#xea07;',
		'ico_plus': '&#xea0a;',
		'ico_minus': '&#xea0b;',
		'ico_cross': '&#xea0f;',
		'ico_exit': '&#xea14;',
		'ico_circle-up': '&#xea41;',
		'ico_circle-right': '&#xea42;',
		'ico_circle-down': '&#xea43;',
		'ico_circle-left': '&#xea44;',
		'ico_checkbox-checked': '&#xea52;',
		'ico_tel': '&#xe601;',
		'ico_email': '&#xe602;',
		'ico_lock': '&#xe603;',
		'ico_cog': '&#xe604;',
		'ico_pencil': '&#xe605;',
		'ico_search': '&#xe600;',
		'0': 0
		},
		els = document.getElementsByTagName('*'),
		i, c, el;
	for (i = 0; ; i += 1) {
		el = els[i];
		if(!el) {
			break;
		}
		c = el.className;
		c = c.match(/ico_[^\s'"]+/);
		if (c && icons[c[0]]) {
			addIcon(el, icons[c[0]]);
		}
	}
}());
