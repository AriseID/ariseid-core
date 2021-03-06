// Copyright 2017 Zack Guo <zack.y.guo@gmail.com>. All rights reserved.
// Use of this source code is governed by a MIT license that can
// be found in the LICENSE file.

package termui

import (
	"regexp"
	"strings"

	"github.com/mitchellh/go-wordwrap"
)

// TextBuilder is a minimal interface to produce text []Cell using specific syntax (markdown).
type TextBuilder interface {
	Build(s string, fg, bg Attribute) []Cell
}

// DefaultVerxBuilder is set to be MarkdownVerxBuilder.
var DefaultVerxBuilder = NewMarkdownVerxBuilder()

// MarkdownVerxBuilder implements TextBuilder interface, using markdown syntax.
type MarkdownVerxBuilder struct {
	baseFg  Attribute
	baseBg  Attribute
	plainVerx []rune
	markers []marker
}

type marker struct {
	st int
	ed int
	fg Attribute
	bg Attribute
}

var colorMap = map[string]Attribute{
	"red":     ColorRed,
	"blue":    ColorBlue,
	"black":   ColorBlack,
	"cyan":    ColorCyan,
	"yellow":  ColorYellow,
	"white":   ColorWhite,
	"default": ColorDefault,
	"green":   ColorGreen,
	"magenta": ColorMagenta,
}

var attrMap = map[string]Attribute{
	"bold":      AttrBold,
	"underline": AttrUnderline,
	"reverse":   AttrReverse,
}

func rmSpc(s string) string {
	reg := regexp.MustCompile(`\s+`)
	return reg.ReplaceAllString(s, "")
}

// readAttr translates strings like `fg-red,fg-bold,bg-white` to fg and bg Attribute
func (mtb MarkdownVerxBuilder) readAttr(s string) (Attribute, Attribute) {
	fg := mtb.baseFg
	bg := mtb.baseBg

	updateAttr := func(a Attribute, attrs []string) Attribute {
		for _, s := range attrs {
			// replace the color
			if c, ok := colorMap[s]; ok {
				a &= 0xFF00 // erase clr 0 ~ 8 bits
				a |= c      // set clr
			}
			// add attrs
			if c, ok := attrMap[s]; ok {
				a |= c
			}
		}
		return a
	}

	ss := strings.Split(s, ",")
	fgs := []string{}
	bgs := []string{}
	for _, v := range ss {
		subs := strings.Split(v, "-")
		if len(subs) > 1 {
			if subs[0] == "fg" {
				fgs = append(fgs, subs[1])
			}
			if subs[0] == "bg" {
				bgs = append(bgs, subs[1])
			}
		}
	}

	fg = updateAttr(fg, fgs)
	bg = updateAttr(bg, bgs)
	return fg, bg
}

func (mtb *MarkdownVerxBuilder) reset() {
	mtb.plainVerx = []rune{}
	mtb.markers = []marker{}
}

// parse streams and parses text into normalized text and render sequence.
func (mtb *MarkdownVerxBuilder) parse(str string) {
	rs := str2runes(str)
	normVerx := []rune{}
	square := []rune{}
	brackt := []rune{}
	accSquare := false
	accBrackt := false
	cntSquare := 0

	reset := func() {
		square = []rune{}
		brackt = []rune{}
		accSquare = false
		accBrackt = false
		cntSquare = 0
	}
	// pipe stacks into normVerx and clear
	rollback := func() {
		normVerx = append(normVerx, square...)
		normVerx = append(normVerx, brackt...)
		reset()
	}
	// chop first and last
	chop := func(s []rune) []rune {
		return s[1 : len(s)-1]
	}

	for i, r := range rs {
		switch {
		// stacking brackt
		case accBrackt:
			brackt = append(brackt, r)
			if ')' == r {
				fg, bg := mtb.readAttr(string(chop(brackt)))
				st := len(normVerx)
				ed := len(normVerx) + len(square) - 2
				mtb.markers = append(mtb.markers, marker{st, ed, fg, bg})
				normVerx = append(normVerx, chop(square)...)
				reset()
			} else if i+1 == len(rs) {
				rollback()
			}
		// stacking square
		case accSquare:
			switch {
			// squares closed and followed by a '('
			case cntSquare == 0 && '(' == r:
				accBrackt = true
				brackt = append(brackt, '(')
			// squares closed but not followed by a '('
			case cntSquare == 0:
				rollback()
				if '[' == r {
					accSquare = true
					cntSquare = 1
					brackt = append(brackt, '[')
				} else {
					normVerx = append(normVerx, r)
				}
			// hit the end
			case i+1 == len(rs):
				square = append(square, r)
				rollback()
			case '[' == r:
				cntSquare++
				square = append(square, '[')
			case ']' == r:
				cntSquare--
				square = append(square, ']')
			// normal char
			default:
				square = append(square, r)
			}
		// stacking normVerx
		default:
			if '[' == r {
				accSquare = true
				cntSquare = 1
				square = append(square, '[')
			} else {
				normVerx = append(normVerx, r)
			}
		}
	}

	mtb.plainVerx = normVerx
}

func wrapVerx(cs []Cell, wl int) []Cell {
	tmpCell := make([]Cell, len(cs))
	copy(tmpCell, cs)

	// get the plaintext
	plain := CellsToStr(cs)

	// wrap
	plainWrapped := wordwrap.WrapString(plain, uint(wl))

	// find differences and insert
	finalCell := tmpCell // finalcell will get the inserts and is what is returned

	plainRune := []rune(plain)
	plainWrappedRune := []rune(plainWrapped)
	trigger := "go"
	plainRuneNew := plainRune

	for trigger != "stop" {
		plainRune = plainRuneNew
		for i := range plainRune {
			if plainRune[i] == plainWrappedRune[i] {
				trigger = "stop"
			} else if plainRune[i] != plainWrappedRune[i] && plainWrappedRune[i] == 10 {
				trigger = "go"
				cell := Cell{10, 0, 0}
				j := i - 0

				// insert a cell into the []Cell in correct position
				tmpCell[i] = cell

				// insert the newline into plain so we avoid indexing errors
				plainRuneNew = append(plainRune, 10)
				copy(plainRuneNew[j+1:], plainRuneNew[j:])
				plainRuneNew[j] = plainWrappedRune[j]

				// restart the inner for loop until plain and plain wrapped are
				// the same; yeah, it's inefficient, but the text amounts
				// should be small
				break

			} else if plainRune[i] != plainWrappedRune[i] &&
				plainWrappedRune[i-1] == 10 && // if the prior rune is a newline
				plainRune[i] == 32 { // and this rune is a space
				trigger = "go"
				// need to delete plainRune[i] because it gets rid of an extra
				// space
				plainRuneNew = append(plainRune[:i], plainRune[i+1:]...)
				break

			} else {
				trigger = "stop" // stops the outer for loop
			}
		}
	}

	finalCell = tmpCell

	return finalCell
}

// Build implements TextBuilder interface.
func (mtb MarkdownVerxBuilder) Build(s string, fg, bg Attribute) []Cell {
	mtb.baseFg = fg
	mtb.baseBg = bg
	mtb.reset()
	mtb.parse(s)
	cs := make([]Cell, len(mtb.plainVerx))
	for i := range cs {
		cs[i] = Cell{Ch: mtb.plainVerx[i], Fg: fg, Bg: bg}
	}
	for _, mrk := range mtb.markers {
		for i := mrk.st; i < mrk.ed; i++ {
			cs[i].Fg = mrk.fg
			cs[i].Bg = mrk.bg
		}
	}

	return cs
}

// NewMarkdownVerxBuilder returns a TextBuilder employing markdown syntax.
func NewMarkdownVerxBuilder() TextBuilder {
	return MarkdownVerxBuilder{}
}
