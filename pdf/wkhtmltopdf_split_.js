//
//
// https://gist.githubusercontent.com/niflostancu/3683510/raw/0d9f043aa5637ab0f7dda89e1b006a0a6ac1c88c/wkhtmltopdf.tablesplit.js
//
//

/**
 * WkHtmlToPdf table splitting hack.
 * 
 * Script to automatically split multiple-pages-spanning HTML tables for PDF 
 * generation using webkit.
 * 
 * To use, you must adjust pdfPage object's contents to reflect your PDF's 
 * page format. 
 * The tables you want to be automatically splitted when the page ends must 
 * have a class name of "splitForPrint" (can be changed).
 * Also, it might be a good idea to update the splitThreshold value if you have 
 * large table rows.
 * 
 * Dependencies: jQuery.
 * 
 * WARNING: WorksForMe(tm)! 
 * If it doesn't work, first check for javascript errors using a webkit browser.
 * 
 * Also, the newest wkhtmltopdf (>= 0.12) fixed this bug, so the script isn't necessary anymore.
 * Use it only if you're stuck with an older version.
 * 
 * Care must be taken if your PDF includes some responsive framework (Bootstrap, Foundation) that makes 
 * use of CSS @media!
 * 
 * @author Florin Stancu <niflostancu@gmail.com>
 * @version 1.1
 * @license http://www.opensource.org/licenses/mit-license.php MIT License
 */


/**
 * PDF page settings.
 * Must have the correct values for the script to work.
 * All numbers must be in inches (as floats)!
 * Use google to convert margins from mm to in ;) 
 * 
 * @type {Object}
 */
var pdfPage = {
	width: 8.26771654, // inches, 210mm
	height: 11.6929134, // inches, 296mm
	margins: {
		top: 1.96850394, left: 0.393700787, 
		right: 0.393700787, bottom: 0.393700787 
	}
};

/**
 * The distance to bottom of which if the element is closer, it should moved on 
 * the next page. Should be at least the element (TR)'s height.
 * 
 * @deprecated Now it is automatically detected from the TR's height, no longer needed.
 * @type {Number}
 */
var splitThreshold = 20;

/**
 * Class name of the tables to automatically split.
 * Should not contain any CSS definitions because it is automatically removed 
 * after the split.
 * 
 * @type {String}
 */
var splitClassName = 'splitForPrint';

/**
 * Set to true to enable visual debugging of the page dimensions via HTML elements / text.
 */
var visualDebug = false;


/**
 * Window load event handler.
 * We use this instead of DOM ready because webkit doesn't load the images yet.
 */
$(window).load(function () {
	// get document resolution
	var dpi = $('<div id="dpi"></div>')
		.css({
			height: '1in', width: '1in',
			top: '-100%', left: '-100%',
			position: 'absolute'
		})
		.appendTo('body')
		.height();
	
	// page height in pixels
	var pageHeight = Math.floor(
		(pdfPage.height - pdfPage.margins.top - pdfPage.margins.bottom) * dpi);
	
	// temporary set body's width and padding to match pdf's size
	var $body = $('body');
	$body.css('width', Math.floor((pdfPage.width - pdfPage.margins.left - pdfPage.margins.right)*dpi)+'px');
	$body.css('padding-left', Math.floor(pdfPage.margins.left*dpi)+'px');
	$body.css('padding-right', Math.floor(pdfPage.margins.right*dpi)+'px');
	//$body.css('padding-top', Math.floor(pdfPage.margins.top*dpi)+'px');
	$body.css('padding-top', 0);
	
	// DEBUG: show the page height (must be an exact fit to the page's content area in order for the script to work)
	if (visualDebug) {
		$body.append('<div id="debug_div" style="position: absolute; top: 0; height:' + (pageHeight - 2) + 'px; ' + 
				'right: 0; border: 1px solid #FF0000; background: blue; color: white;">Test<br />' + pageHeight + '<br /></div>');
		$('#debug_div').append( $('#debug_div').offset().top + '');
	}
	
	/* 
	 * Cycle through all tables and split them in two if necessary.
	 * We need this in a loop for it to work for tables spanning multiple pages:
	 * first, the table is split in two; then, if the second table also spans multiple 
	 * pages, it is also split and so on until there are no more.
	 * Because when modifying the upper tables, the elements' positions will change, 
	 * we need to maintain an offset correction value.
	 * 
	 * This method can be used for all document's elements (not just tables), but the 
	 * overhead would be too big. Use CSS's `page-break-inside: avoid` which works for
	 * divs and many other block elements.
	 */
	var tablesModified = true;
	var offsetCorrection = 0;
	while (tablesModified) {
		tablesModified = false;
		
		$('table.'+splitClassName).each(function(){
			var $t = $(this);
			
			// clone the original table
			var copy = $t.clone();
			copy.find('tbody > tr').remove();
			var $cbody = copy.find('tbody');
			var found = false;
			$t.removeClass(splitClassName); // for optimisation
			
			var newOffsetCorrection = offsetCorrection;
			$('tbody tr', $t).each(function(){
				var $tr = $(this);
				
				// compute element's top position and page's end
				var top = $tr.offset().top;
				var ctop = offsetCorrection + top;
				var pageEnd = (Math.floor(ctop/pageHeight)+1)*pageHeight;
				
				// DEBUG: prints TR's top and the current page end inside its first column
				if (visualDebug) {
					//if (Math.random() > 0.7)
					//	$tr.find('td:first').append('<br /> MULTI!');
					$tr.find('td:first').prepend('<div style="position: absolute;  z-index:2; background: #EEE; padding: 2px;" class="debug">' +
						ctop + ' / ' + pageEnd + '/ off=' + offsetCorrection + ' / h=<span class="tr-height">-</span>px' + '</div>' );
				}
				
				// check whether the current element is close to the page's end. 
				// dynamic threshold
				var threshold = splitThreshold;
				if ($tr.height() > threshold)
					threshold = $tr.height() + 10;
				if (visualDebug)
					$tr.find('.tr-height').text($tr.height());
				
				if (found || (ctop >= (pageEnd - threshold))) {
					// move the element to the cloned table
					$tr.detach().appendTo($cbody);
					if (visualDebug) $tr.find('td .debug').append(' D!');
					
					if (!found) {
						// compute the new offset correction
						newOffsetCorrection += (pageEnd - ctop);
					}
					found = true;
				}
			});
			
			// if the cloned table has no contents...
			if (!found) 
				return;
			
			offsetCorrection = newOffsetCorrection;
			tablesModified = true;
			// add a page-breaking div 
			// (with some whitespace to correctly show table top border)
			var $br = $('<div style="height: 15px;"></div>')
				.css('page-break-before', 'always');
			$br.insertAfter($t);
			copy.insertAfter($br);
		});
	}
	
	// restore body's padding
	$body.css('padding-left', 0);
	$body.css('padding-right', 0);
	$body.css('padding-top', 0);
});
