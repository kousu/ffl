/*! modernizr 3.2.0 (Custom Build) | MIT *
 * http://modernizr.com/download/?-inputtypes-setclasses-testallprops !*/
!function(e,t,n){function r(e,t){return typeof e===t}function i(){var e,t,n,i,o,s,l;for(var a in C)if(C.hasOwnProperty(a)){if(e=[],t=C[a],t.name&&(e.push(t.name.toLowerCase()),t.options&&t.options.aliases&&t.options.aliases.length))for(n=0;n<t.options.aliases.length;n++)e.push(t.options.aliases[n].toLowerCase());for(i=r(t.fn,"function")?t.fn():t.fn,o=0;o<e.length;o++)s=e[o],l=s.split("."),1===l.length?Modernizr[l[0]]=i:(!Modernizr[l[0]]||Modernizr[l[0]]instanceof Boolean||(Modernizr[l[0]]=new Boolean(Modernizr[l[0]])),Modernizr[l[0]][l[1]]=i),g.push((i?"":"no-")+l.join("-"))}}function o(e){var t=b.className,n=Modernizr._config.classPrefix||"";if(S&&(t=t.baseVal),Modernizr._config.enableJSClass){var r=new RegExp("(^|\\s)"+n+"no-js(\\s|$)");t=t.replace(r,"$1"+n+"js$2")}Modernizr._config.enableClasses&&(t+=" "+n+e.join(" "+n),S?b.className.baseVal=t:b.className=t)}function s(){return"function"!=typeof t.createElement?t.createElement(arguments[0]):S?t.createElementNS.call(t,"http://www.w3.org/2000/svg",arguments[0]):t.createElement.apply(t,arguments)}function l(e,t){return!!~(""+e).indexOf(t)}function a(e){return e.replace(/([a-z])-([a-z])/g,function(e,t,n){return t+n.toUpperCase()}).replace(/^-/,"")}function u(e,t){return function(){return e.apply(t,arguments)}}function f(e,t,n){var i;for(var o in e)if(e[o]in t)return n===!1?e[o]:(i=t[e[o]],r(i,"function")?u(i,n||t):i);return!1}function p(e){return e.replace(/([A-Z])/g,function(e,t){return"-"+t.toLowerCase()}).replace(/^ms-/,"-ms-")}function d(){var e=t.body;return e||(e=s(S?"svg":"body"),e.fake=!0),e}function c(e,n,r,i){var o,l,a,u,f="modernizr",p=s("div"),c=d();if(parseInt(r,10))for(;r--;)a=s("div"),a.id=i?i[r]:f+(r+1),p.appendChild(a);return o=s("style"),o.type="text/css",o.id="s"+f,(c.fake?c:p).appendChild(o),c.appendChild(p),o.styleSheet?o.styleSheet.cssText=e:o.appendChild(t.createTextNode(e)),p.id=f,c.fake&&(c.style.background="",c.style.overflow="hidden",u=b.style.overflow,b.style.overflow="hidden",b.appendChild(c)),l=n(p,e),c.fake?(c.parentNode.removeChild(c),b.style.overflow=u,b.offsetHeight):p.parentNode.removeChild(p),!!l}function m(t,r){var i=t.length;if("CSS"in e&&"supports"in e.CSS){for(;i--;)if(e.CSS.supports(p(t[i]),r))return!0;return!1}if("CSSSupportsRule"in e){for(var o=[];i--;)o.push("("+p(t[i])+":"+r+")");return o=o.join(" or "),c("@supports ("+o+") { #modernizr { position: absolute; } }",function(e){return"absolute"==getComputedStyle(e,null).position})}return n}function h(e,t,i,o){function u(){p&&(delete N.style,delete N.modElem)}if(o=r(o,"undefined")?!1:o,!r(i,"undefined")){var f=m(e,i);if(!r(f,"undefined"))return f}for(var p,d,c,h,y,v=["modernizr","tspan"];!N.style;)p=!0,N.modElem=s(v.shift()),N.style=N.modElem.style;for(c=e.length,d=0;c>d;d++)if(h=e[d],y=N.style[h],l(h,"-")&&(h=a(h)),N.style[h]!==n){if(o||r(i,"undefined"))return u(),"pfx"==t?h:!0;try{N.style[h]=i}catch(g){}if(N.style[h]!=y)return u(),"pfx"==t?h:!0}return u(),!1}function y(e,t,n,i,o){var s=e.charAt(0).toUpperCase()+e.slice(1),l=(e+" "+P.join(s+" ")+s).split(" ");return r(t,"string")||r(t,"undefined")?h(l,t,i,o):(l=(e+" "+z.join(s+" ")+s).split(" "),f(l,t,n))}function v(e,t,r){return y(e,n,n,t,r)}var g=[],C=[],w={_version:"3.2.0",_config:{classPrefix:"",enableClasses:!0,enableJSClass:!0,usePrefixes:!0},_q:[],on:function(e,t){var n=this;setTimeout(function(){t(n[e])},0)},addTest:function(e,t,n){C.push({name:e,fn:t,options:n})},addAsyncTest:function(e){C.push({name:null,fn:e})}},Modernizr=function(){};Modernizr.prototype=w,Modernizr=new Modernizr;var b=t.documentElement,S="svg"===b.nodeName.toLowerCase(),_=s("input"),x="search tel url email datetime date month week time datetime-local number range color".split(" "),k={};Modernizr.inputtypes=function(e){for(var r,i,o,s=e.length,l="1)",a=0;s>a;a++)_.setAttribute("type",r=e[a]),o="text"!==_.type&&"style"in _,o&&(_.value=l,_.style.cssText="position:absolute;visibility:hidden;",/^range$/.test(r)&&_.style.WebkitAppearance!==n?(b.appendChild(_),i=t.defaultView,o=i.getComputedStyle&&"textfield"!==i.getComputedStyle(_,null).WebkitAppearance&&0!==_.offsetHeight,b.removeChild(_)):/^(search|tel)$/.test(r)||(o=/^(url|email)$/.test(r)?_.checkValidity&&_.checkValidity()===!1:_.value!=l)),k[e[a]]=!!o;return k}(x);var E="Moz O ms Webkit",P=w._config.usePrefixes?E.split(" "):[];w._cssomPrefixes=P;var z=w._config.usePrefixes?E.toLowerCase().split(" "):[];w._domPrefixes=z;var A={elem:s("modernizr")};Modernizr._q.push(function(){delete A.elem});var N={style:A.elem.style};Modernizr._q.unshift(function(){delete N.style}),w.testAllProps=y,w.testAllProps=v,i(),o(g),delete w.addTest,delete w.addAsyncTest;for(var T=0;T<Modernizr._q.length;T++)Modernizr._q[T]();e.Modernizr=Modernizr}(window,document);