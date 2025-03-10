/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *   Product name: redemption, a FLOSS RDP proxy
 *   Copyright (C) Wallix 2010-2013
 *   Author(s): Christophe Grosjean, Dominique Lafages, Jonathan Poelen,
 *              Meng Tan
 */

#include "mod/internal/widget/password.hpp"
#include "mod/internal/copy_paste.hpp"
#include "keyboard/keymap.hpp"
#include "gdi/graphic_api.hpp"
#include "gdi/text_metrics.hpp"
#include "utils/utf.hpp"

WidgetPassword::WidgetPassword(
    gdi::GraphicApi & drawable, CopyPaste & copy_paste,
    const char * text, WidgetEventNotifier onsubmit,
    Color fgcolor, Color bgcolor, Color focus_color,
    Font const & font, std::size_t edit_position, int xtext, int ytext
)
    : WidgetEdit(drawable, copy_paste, text, onsubmit,
                 fgcolor, bgcolor, focus_color, font, edit_position, xtext, ytext)
    , masked_text(drawable, text, fgcolor, bgcolor, font, xtext, ytext)
{
    set_masked_text();

    gdi::TextMetrics tm(font, "*");
    this->w_char = tm.width;
    this->h_char = tm.height;
    this->h_char -= 1;
}

Dimension WidgetPassword::get_optimal_dim() const
{
    Dimension dim = this->masked_text.get_optimal_dim();

    dim.w += 2;
    dim.h += 2;

    return dim;
}

void WidgetPassword::set_masked_text()
{
    if(!is_password_visible) {
        // Set hidden text
        char buff[WidgetLabel::buffer_size];
        for (size_t n = 0; n < this->num_chars; ++n) {
            buff[n] = '*';
        }
        buff[this->num_chars] = 0;
        this->masked_text.set_text(buff);
    }
    else
    {
        // Set visible text
        this->masked_text.set_text(chars_view(WidgetEdit::get_text()));
    }
}

void WidgetPassword::set_xy(int16_t x, int16_t y)
{
    WidgetEdit::set_xy(x, y);
    this->masked_text.set_xy(x + 1, y + 1);
}

void WidgetPassword::set_wh(uint16_t w, uint16_t h)
{
    WidgetEdit::set_wh(w, h);
    this->masked_text.set_wh(w - 2, h - 2);
}

void WidgetPassword::set_text(const char * text)
{
   WidgetEdit::set_text(text);
   this->set_masked_text();
}

void WidgetPassword::insert_text(const char* text)
{
    WidgetEdit::insert_text(text);
    this->set_masked_text();
    this->rdp_input_invalidate(this->get_rect());
}

void WidgetPassword::toggle_password_visibility() {
    is_password_visible = !is_password_visible;
    set_masked_text();
    this->rdp_input_invalidate(this->get_rect());
}

void WidgetPassword::hide_password_text()
{
    if(is_password_visible) {
        is_password_visible = false;
        set_masked_text();
        this->rdp_input_invalidate(this->get_rect());
    }
}

void WidgetPassword::show_password_text()
{
    if(!is_password_visible) {
        is_password_visible = true;
        set_masked_text();
        this->rdp_input_invalidate(this->get_rect());
    }
}

void WidgetPassword::rdp_input_invalidate(Rect clip)
{
    Rect rect_intersect = clip.intersect(this->get_rect());

    if (!rect_intersect.isempty()) {
        this->masked_text.rdp_input_invalidate(rect_intersect);
        if (this->has_focus) {
            this->draw_cursor(this->get_cursor_rect());
            this->draw_border(rect_intersect, this->focus_color);
        }
        else {
            this->draw_border(rect_intersect, this->label.bg_color);
        }
    }
}

void WidgetPassword::update_draw_cursor(Rect old_cursor)
{
    if(is_password_visible) {
        WidgetEdit::update_draw_cursor(old_cursor);
    }
    else{
        this->masked_text.rdp_input_invalidate(old_cursor);
        auto cursort_rect = this->get_cursor_rect();
        auto rect = this->get_rect();
        if (rect.x + 1 < cursort_rect.x && cursort_rect.x < rect.eright()) {
            this->draw_cursor(cursort_rect);
        }
    }
}


Rect WidgetPassword::get_cursor_rect() const
{
    if(is_password_visible) {
        return WidgetEdit::get_cursor_rect();
    }

    return Rect(this->masked_text.x_text + this->edit_pos * this->w_char + this->x() + 2,
                this->masked_text.y_text + this->masked_text.y(),
                1,
                this->h_char);
}

void WidgetPassword::rdp_input_mouse(uint16_t device_flags, uint16_t x, uint16_t y)
{
    if (device_flags == (MOUSE_FLAG_BUTTON1|MOUSE_FLAG_DOWN)) {
        WidgetEdit::rdp_input_mouse(device_flags, x, y);

        const WidgetLabel& text_label = is_password_visible? label : masked_text;

        Rect old_cursor_rect = this->get_cursor_rect();
        size_t e = this->edit_pos;
        if (x <= this->x() + text_label.x_text + this->w_char/2) {
            this->edit_pos = 0;
            this->edit_buffer_pos = 0;
        }
        else if (x >= int(this->x() + text_label.x_text + this->w_char * this->num_chars)) {
            if (this->edit_pos < this->num_chars) {
                this->edit_pos = this->num_chars;
                this->edit_buffer_pos = this->buffer_size;
            }
        }
        else {

                //      dx
                // <---------->
                //           x
                // <------------------->
                //     -x_text
                //     <------>             screen
                // +-------------------------------------------------------------
                // |                        editbox
                // |           +--------------------------------+
                // |   {.......|.......X................}       |
                // |           +--------------------------------+
                // |   <--------------->
                // |   (x - dx - x_text)
                // |

            this->edit_pos = std::min<size_t>((x - this->x() - text_label.x_text - this->w_char/2) / this->w_char, this->num_chars-1);
            this->edit_buffer_pos = UTF8GetPos(byte_ptr_cast(&this->label.buffer[0]), this->edit_pos);
        }
        if (e != this->edit_pos) {
            this->update_draw_cursor(old_cursor_rect);
        }
    }
}

void WidgetPassword::rdp_input_scancode(
    KbdFlags flags, Scancode scancode, uint32_t event_time, Keymap const& keymap)
{
    REDEMPTION_DIAGNOSTIC_PUSH()
    REDEMPTION_DIAGNOSTIC_GCC_IGNORE("-Wswitch-enum")
    switch (keymap.last_kevent()) {
        case Keymap::KEvent::Paste:
            this->copy_paste.paste(*this);
            break;
        case Keymap::KEvent::Copy:
            return;
        case Keymap::KEvent::Cut:
            this->set_text("");
            break;
        default:
            WidgetEdit::rdp_input_scancode(flags, scancode, event_time, keymap);
    }

    switch (keymap.last_kevent()) {
        case Keymap::KEvent::Backspace:
        case Keymap::KEvent::Delete:
        case Keymap::KEvent::KeyDown:
        case Keymap::KEvent::Paste:
        case Keymap::KEvent::Cut:
            this->set_masked_text();
            [[fallthrough]];

        case Keymap::KEvent::LeftArrow:
        case Keymap::KEvent::UpArrow:
        case Keymap::KEvent::RightArrow:
        case Keymap::KEvent::DownArrow:
        case Keymap::KEvent::End:
        case Keymap::KEvent::Home:
            this->masked_text.shift_text(this->edit_pos * this->w_char);
            this->rdp_input_invalidate(this->get_rect());
            break;

        default:
            break;
    }
    REDEMPTION_DIAGNOSTIC_POP()
}

void WidgetPassword::rdp_input_unicode(KbdFlags flag, uint16_t unicode)
{
    WidgetEdit::rdp_input_unicode(flag, unicode);
    this->set_masked_text();

    this->masked_text.shift_text(this->edit_pos * this->w_char);

    this->rdp_input_invalidate(this->get_rect());
}
