/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1 of the License, or
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
 *   Copyright (C) Wallix 2010-2014
 *   Author(s): Christophe Grosjean, Dominique Lafages, Jonathan Poelen,
 *              Meng Tan
 */

#include "core/RDP/orders/RDPOrdersPrimaryOpaqueRect.hpp"
#include "core/font.hpp"
#include "gdi/graphic_api.hpp"
#include "gdi/text_metrics.hpp"
#include "keyboard/keymap.hpp"
#include "mod/internal/widget/edit.hpp"
#include "mod/internal/copy_paste.hpp"
#include "utils/colors.hpp"
#include "utils/sugar/cast.hpp"
#include "utils/utf.hpp"


WidgetEdit::WidgetEdit(
    gdi::GraphicApi & drawable, CopyPaste & copy_paste,
    const char * text, WidgetEventNotifier onsubmit,
    Color fgcolor, Color bgcolor, Color focus_color,
    Font const & font, std::size_t edit_position, int xtext, int ytext)
: Widget(drawable, Focusable::Yes)
, onsubmit(onsubmit)
, label(drawable, text, fgcolor, bgcolor, font, xtext, ytext)
, w_text(0)
, h_text(font.max_height())
, cursor_color(0x888888)
, focus_color(focus_color)
, drawall(false)
, font(font)
, copy_paste(copy_paste)
{
    if (text) {
        this->buffer_size = strlen(text);
        this->num_chars = UTF8Len(byte_ptr_cast(this->label.buffer));
        this->edit_pos = std::min(this->num_chars, edit_position);
        this->edit_buffer_pos = UTF8GetPos(byte_ptr_cast(this->label.buffer), this->edit_pos);
        this->cursor_px_pos = 0;
        char c = this->label.buffer[this->edit_buffer_pos];
        this->label.buffer[this->edit_buffer_pos] = 0;
        gdi::TextMetrics tm1(this->font, this->label.buffer);
        this->w_text = tm1.width;
        this->cursor_px_pos = this->w_text;
        this->label.buffer[this->edit_buffer_pos] = c;
        // TODO: tm.height unused ?
        gdi::TextMetrics tm2(this->font, &this->label.buffer[this->edit_buffer_pos]);
        this->w_text += tm2.width;
    } else {
        this->buffer_size = 0;
        this->num_chars = 0;
        this->edit_buffer_pos = 0;
        this->edit_pos = 0;
        this->cursor_px_pos = 0;
    }

    this->pointer_flag = PointerType::Edit;
}

WidgetEdit::~WidgetEdit()
{
    this->copy_paste.stop_paste_for(*this);
}

Dimension WidgetEdit::get_optimal_dim() const
{
    Dimension dim = this->label.get_optimal_dim();

    dim.w += 2;
    dim.h += 2;

    return dim;
}

void WidgetEdit::set_text(const char * text/*, int position = 0*/)
{
    this->label.buffer[0] = 0;
    this->buffer_size = 0;
    this->num_chars = 0;
    this->w_text = 0;
    if (text && *text) {
        const size_t n = strlen(text);
        const size_t remain_n = WidgetLabel::buffer_size - 1;

        this->buffer_size = ((remain_n >= n) ? n : ::UTF8StringAdjustedNbBytes(::byte_ptr_cast(text), remain_n));

        memcpy(this->label.buffer, text, this->buffer_size);
        this->label.buffer[this->buffer_size] = 0;
        gdi::TextMetrics tm(this->font, this->label.buffer);
        this->w_text = tm.width;
        this->num_chars = UTF8Len(byte_ptr_cast(this->label.buffer));
    }
    this->edit_pos = this->num_chars;
    this->edit_buffer_pos = this->buffer_size;
    this->cursor_px_pos = this->w_text;
}

void WidgetEdit::insert_text(const char * text/*, int position = 0*/)
{
    if (text && *text) {
        const size_t n = strlen(text);
        const size_t tmp_buffer_size = this->buffer_size;

        const size_t remain_n = WidgetLabel::buffer_size - 1 - this->buffer_size;
        const size_t max_n = ((remain_n >= n) ? n : ::UTF8StringAdjustedNbBytes(::byte_ptr_cast(text), remain_n));
        const size_t total_n = max_n + this->buffer_size;

        if (this->edit_pos == this->buffer_size || total_n == WidgetLabel::buffer_size - 1) {
            memcpy(this->label.buffer + this->buffer_size, text, max_n);
        }
        else {
            memmove(this->label.buffer + this->edit_buffer_pos + n, this->label.buffer + this->edit_buffer_pos,
                    std::min(WidgetLabel::buffer_size - 1 - (this->edit_buffer_pos + n),
                                this->buffer_size - this->edit_buffer_pos));
            memcpy(this->label.buffer + this->edit_buffer_pos, text, max_n);
        }
        this->buffer_size = total_n;
        this->label.buffer[this->buffer_size] = 0;
        gdi::TextMetrics tm(this->font, this->label.buffer);
        this->w_text = tm.width;
        const size_t tmp_num_chars = this->num_chars;
        this->num_chars = UTF8Len(byte_ptr_cast(this->label.buffer));
        Rect rect = this->get_cursor_rect();
        rect.cx = this->w_text - this->cursor_px_pos;
        if (this->edit_pos == tmp_buffer_size || total_n == WidgetLabel::buffer_size - 1) {
            this->cursor_px_pos = this->w_text;
            this->edit_buffer_pos = this->buffer_size;
        }
        else {
            const size_t pos = this->edit_buffer_pos + max_n;
            const char c = this->label.buffer[pos];
            this->label.buffer[pos] = 0;
            // TODO: tm.height unused ?
            gdi::TextMetrics tm(this->font, this->label.buffer + this->edit_buffer_pos);
            this->label.buffer[pos] = c;
            this->cursor_px_pos += tm.width;
            this->edit_buffer_pos += max_n;
        }
        this->edit_pos += this->num_chars - tmp_num_chars;
        this->update_draw_cursor(rect);
    }
}

zstring_view WidgetEdit::get_text() const
{
    return zstring_view::from_null_terminated(this->label.get_text());
}

void WidgetEdit::set_xy(int16_t x, int16_t y)
{
    Widget::set_xy(x, y);
    this->label.set_xy(x + 1, y + 1);
}

void WidgetEdit::set_wh(uint16_t w, uint16_t h)
{
    Widget::set_wh(w, h);
    this->label.set_wh(w - 2, h - 2);
}

void WidgetEdit::rdp_input_invalidate(Rect clip)
{
    Rect rect_intersect = clip.intersect(this->get_rect());

    if (!rect_intersect.isempty()) {
        this->label.rdp_input_invalidate(rect_intersect);
        if (this->has_focus) {
            this->draw_cursor(this->get_cursor_rect());
            this->draw_border(rect_intersect, this->focus_color);
        }
        else {
            this->draw_border(rect_intersect, this->label.bg_color);
        }
    }
}

void WidgetEdit::draw_border(Rect clip, Color color)
{
    //top
    this->drawable.draw(RDPOpaqueRect(clip.intersect(Rect(
        this->x(), this->y(), this->cx() - 1, 1
    )), color), clip, gdi::ColorCtx::depth24());
    //left
    this->drawable.draw(RDPOpaqueRect(clip.intersect(Rect(
        this->x(), this->y() + 1, 1, this->cy() - 2
    )), color), clip, gdi::ColorCtx::depth24());
    //right
    this->drawable.draw(RDPOpaqueRect(clip.intersect(Rect(
        this->x() + this->cx() - 1, this->y(), 1, this->cy()
    )), color), clip, gdi::ColorCtx::depth24());
    //bottom
    this->drawable.draw(RDPOpaqueRect(clip.intersect(Rect(
        this->x(), this->y() + this->cy() - 1, this->cx(), 1
    )), color), clip, gdi::ColorCtx::depth24());
}

Rect WidgetEdit::get_cursor_rect() const
{
    return Rect(this->label.x_text + this->cursor_px_pos + this->label.x() + 1,
                this->label.y_text + this->label.y(),
                1,
                this->h_text);
}

void WidgetEdit::draw_current_cursor()
{
    if (this->has_focus) {
        this->draw_cursor(this->get_cursor_rect());
    }
}

void WidgetEdit::draw_cursor(const Rect clip)
{
    if (!clip.isempty()) {
        this->drawable.draw(RDPOpaqueRect(clip, this->cursor_color), clip, gdi::ColorCtx::depth24());
    }
}

void WidgetEdit::increment_edit_pos()
{
    this->edit_pos++;
    size_t n = UTF8GetPos(byte_ptr_cast(this->label.buffer + this->edit_buffer_pos), 1);
    char c = this->label.buffer[this->edit_buffer_pos + n];
    this->label.buffer[this->edit_buffer_pos + n] = 0;
    gdi::TextMetrics tm(this->font, this->label.buffer + this->edit_buffer_pos);
    this->cursor_px_pos += tm.width;
    this->label.buffer[this->edit_buffer_pos + n] = c;
    this->edit_buffer_pos += n;

    if (this->label.shift_text(this->cursor_px_pos)) {
        this->drawall = true;
    }
}

size_t WidgetEdit::utf8len_current_char()
{
    size_t len = 1;
    while ((this->label.buffer[this->edit_buffer_pos + len] & 0xC0) == 0x80){
        ++len;
    }
    return len;
}

void WidgetEdit::decrement_edit_pos()
{
    size_t len = 1;
    while (/*this->edit_buffer_pos - len >= 0 &&
            (*/(this->label.buffer[this->edit_buffer_pos - len] & 0xC0) == 0x80/*)*/){
        ++len;
    }

    this->edit_pos--;
    char c = this->label.buffer[this->edit_buffer_pos];
    this->label.buffer[this->edit_buffer_pos] = 0;
    gdi::TextMetrics tm(this->font, this->label.buffer + this->edit_buffer_pos - len);
    this->cursor_px_pos -= tm.width;
    this->label.buffer[this->edit_buffer_pos] = c;
    this->edit_buffer_pos -= len;

    if (this->label.shift_text(this->cursor_px_pos)) {
        this->drawall = true;
    }
}

void WidgetEdit::update_draw_cursor(Rect old_cursor)
{
    if (this->drawall) {
        this->drawall = false;
        this->rdp_input_invalidate(this->get_rect());
    }
    else {
        this->label.rdp_input_invalidate(old_cursor);
        this->draw_cursor(this->get_cursor_rect());
    }
}

void WidgetEdit::move_to_last_character()
{
    Rect old_cursor_rect = this->get_cursor_rect();
    this->edit_pos = this->num_chars;
    this->edit_buffer_pos = this->buffer_size;
    this->cursor_px_pos = this->w_text;

    if (this->label.shift_text(this->cursor_px_pos)) {
        this->drawall = true;
    }

    this->update_draw_cursor(old_cursor_rect);
}

void WidgetEdit::move_to_first_character()
{
    Rect old_cursor_rect = this->get_cursor_rect();
    this->edit_pos = 0;
    this->edit_buffer_pos = 0;
    this->cursor_px_pos = 0;

    if (this->label.shift_text(this->cursor_px_pos)) {
        this->drawall = true;
    }

    this->update_draw_cursor(old_cursor_rect);
}

void WidgetEdit::rdp_input_mouse(uint16_t device_flags, uint16_t x, uint16_t y)
{
    if (device_flags == (MOUSE_FLAG_BUTTON1|MOUSE_FLAG_DOWN)) {
        if (x <= this->x() + this->label.x_text) {
            if (this->edit_pos) {
                this->move_to_first_character();
            }
        }
        else if (x >= this->w_text + this->x() + this->label.x_text) {
            if (this->edit_pos < this->num_chars) {
                this->move_to_last_character();
            }
        }
        else {
            Rect old_cursor_rect = this->get_cursor_rect();
            int xx = this->x() + this->label.x_text;
            size_t e = this->edit_pos;
            this->edit_pos = 0;
            this->edit_buffer_pos = 0;
            size_t len = this->utf8len_current_char();
            while (this->edit_buffer_pos < this->buffer_size) {
                char c = this->label.buffer[this->edit_buffer_pos + len];
                this->label.buffer[this->edit_buffer_pos + len] = 0;
                gdi::TextMetrics tm(this->font, this->label.buffer + this->edit_buffer_pos);
                // TODO: tm.height unused ?
                this->label.buffer[this->edit_buffer_pos + len] = c;
                xx += tm.width;
                if (xx >= x) {
                    xx -= tm.width;
                    break;
                }
                len = this->utf8len_current_char();
                this->edit_buffer_pos += len;
                ++this->edit_pos;
            }
            this->cursor_px_pos = xx - (this->x() + this->label.x_text);
            if (e != this->edit_pos) {
                this->update_draw_cursor(old_cursor_rect);
            }
        }
    } else {
        Widget::rdp_input_mouse(device_flags, x, y);
    }
}

void WidgetEdit::rdp_input_scancode(KbdFlags flags, Scancode scancode, uint32_t event_time, Keymap const& keymap)
{
    REDEMPTION_DIAGNOSTIC_PUSH()
    REDEMPTION_DIAGNOSTIC_GCC_IGNORE("-Wswitch-enum")
    switch (keymap.last_kevent()) {
        case Keymap::KEvent::None:
            break;

        case Keymap::KEvent::LeftArrow:
        case Keymap::KEvent::UpArrow:
            if (this->edit_pos > 0) {
                Rect old_cursor_rect = this->get_cursor_rect();
                this->decrement_edit_pos();
                this->update_draw_cursor(old_cursor_rect);
            }

            if (keymap.is_ctrl_pressed()) {
                while ( (this->label.buffer[(this->edit_buffer_pos)-1] != ' ')
                     || (this->label.buffer[(this->edit_buffer_pos)] == ' ')
                ){
                    if (this->edit_pos > 0) {
                        Rect old_cursor_rect = this->get_cursor_rect();
                        this->decrement_edit_pos();
                        this->update_draw_cursor(old_cursor_rect);
                    }
                    else {
                        break;
                    }
                }
            }
            break;

        case Keymap::KEvent::RightArrow:
        case Keymap::KEvent::DownArrow:
            if (this->edit_pos < this->num_chars) {
                Rect old_cursor_rect = this->get_cursor_rect();
                this->increment_edit_pos();
                this->update_draw_cursor(old_cursor_rect);
            }

            if (keymap.is_ctrl_pressed()) {
                while ( (this->label.buffer[(this->edit_buffer_pos)-1] == ' ')
                        || (this->label.buffer[(this->edit_buffer_pos)] != ' ') ){
                    if (this->edit_pos < this->num_chars) {
                        Rect old_cursor_rect = this->get_cursor_rect();
                        this->increment_edit_pos();
                        this->update_draw_cursor(old_cursor_rect);
                    }
                    else {
                        break;
                    }
                }
            }
            break;

        case Keymap::KEvent::Backspace:
            if (this->edit_pos > 0) {
                auto remove_one_char = [this]{
                    this->num_chars--;
                    size_t pxtmp = this->cursor_px_pos;
                    size_t ebpos = this->edit_buffer_pos;
                    this->decrement_edit_pos();
                    UTF8RemoveOne(make_writable_array_view(this->label.buffer).drop_front(this->edit_buffer_pos));
                    this->buffer_size += this->edit_buffer_pos - ebpos;
                    Rect const rect(
                        this->x() + this->cursor_px_pos + this->label.x_text,
                        this->y() + this->label.y_text + 1,
                        this->w_text - this->cursor_px_pos + 3,
                        this->h_text
                    );
                    this->w_text -= pxtmp - this->cursor_px_pos;
                    return rect;
                };

                if (keymap.is_ctrl_pressed()) {
                    // TODO remove_n_char
                    Rect rect = this->get_cursor_rect();
                    while (this->edit_pos > 0 && this->label.buffer[(this->edit_buffer_pos)-1] == ' ') {
                        rect = rect.disjunct(remove_one_char());
                    }
                    while (this->edit_pos > 0 && this->label.buffer[(this->edit_buffer_pos)-1] != ' ') {
                        rect = rect.disjunct(remove_one_char());
                    }
                    this->rdp_input_invalidate(rect);
                }
                else {
                    this->rdp_input_invalidate(remove_one_char());
                }
            }
            break;

        case Keymap::KEvent::Delete:
            if (this->edit_pos < this->num_chars) {
                auto remove_one_char = [this]{
                    size_t len = this->utf8len_current_char();
                    char c = this->label.buffer[this->edit_buffer_pos + len];
                    this->label.buffer[this->edit_buffer_pos + len] = 0;
                    gdi::TextMetrics tm(this->font, this->label.buffer + this->edit_buffer_pos);
                    this->label.buffer[this->edit_buffer_pos + len] = c;
                    UTF8RemoveOne(make_writable_array_view(this->label.buffer).drop_front(this->edit_buffer_pos));
                    this->buffer_size -= len;
                    this->num_chars--;
                    Rect const rect(
                        this->x() + this->cursor_px_pos + this->label.x_text,
                        this->y() + this->label.y_text + 1,
                        this->w_text - this->cursor_px_pos + 3,
                        this->h_text
                    );
                    this->w_text -= tm.width;
                    return rect;
                };

                if (keymap.is_ctrl_pressed()) {
                    // TODO remove_n_char
                    Rect rect = this->get_cursor_rect();
                    if (this->label.buffer[this->edit_buffer_pos] == ' ') {
                        rect = rect.disjunct(remove_one_char());
                        while (this->edit_pos < this->num_chars && this->label.buffer[this->edit_buffer_pos] == ' ') {
                            rect = rect.disjunct(remove_one_char());
                        }
                    }
                    else {
                        while (this->edit_pos < this->num_chars && this->label.buffer[this->edit_buffer_pos] != ' ') {
                            rect = rect.disjunct(remove_one_char());
                        }
                        while (this->edit_pos < this->num_chars && this->label.buffer[this->edit_buffer_pos] == ' ') {
                            rect = rect.disjunct(remove_one_char());
                        }
                    }
                    this->rdp_input_invalidate(this->get_cursor_rect().disjunct(rect));
                }
                else {
                    this->rdp_input_invalidate(this->get_cursor_rect().disjunct(remove_one_char()));
                }
            }
            break;

        case Keymap::KEvent::End:
            if (this->edit_pos < this->num_chars) {
                this->move_to_last_character();
            }
            break;

        case Keymap::KEvent::Home:
            if (this->edit_pos) {
                this->move_to_first_character();
            }
            break;

        case Keymap::KEvent::KeyDown:
            for (auto uchars : keymap.last_decoded_keys().uchars) {
                if (uchars && this->num_chars < WidgetLabel::buffer_size - 5) {
                    this->insert_unicode_char(uchars);
                }
            }
            break;

        case Keymap::KEvent::Enter:
            this->onsubmit();
            break;

        case Keymap::KEvent::Paste:
            this->copy_paste.paste(*this);
            break;

        case Keymap::KEvent::Copy:
            if (this->copy_paste) {
                this->copy_paste.copy(this->get_text());
            }
            break;

        case Keymap::KEvent::Cut:
            if (this->copy_paste) {
                this->copy_paste.copy(this->get_text());
            }

            this->set_text("");
            this->label.rdp_input_invalidate(this->label.get_rect());
            this->draw_cursor(this->get_cursor_rect());
            break;

        default:
            Widget::rdp_input_scancode(flags, scancode, event_time, keymap);
            break;
    }
    REDEMPTION_DIAGNOSTIC_POP()
}

void WidgetEdit::rdp_input_unicode(KbdFlags flag, uint16_t unicode)
{
    if (bool(flag & KbdFlags::Release)) {
        return;
    }

    this->insert_unicode_char(unicode);
}

void WidgetEdit::insert_unicode_char(uint16_t unicode_char)
{
    auto buf = make_writable_array_view(this->label.buffer).drop_front(this->edit_buffer_pos);
    if (!UTF8InsertUtf16(buf, this->buffer_size - this->edit_buffer_pos + 1, unicode_char)) {
        return ;
    }

    size_t tmp = this->edit_buffer_pos;
    size_t pxtmp = this->cursor_px_pos;
    this->increment_edit_pos();
    this->buffer_size += this->edit_buffer_pos - tmp;
    this->num_chars++;
    this->w_text += this->cursor_px_pos - pxtmp;
    this->update_draw_cursor(Rect(
        this->x() + pxtmp + this->label.x_text,
        this->y() + this->label.y_text + 1,
        this->w_text - pxtmp + 2,
        this->h_text
    ));
}

void WidgetEdit::clipboard_insert_utf8(zstring_view text)
{
    auto is_special_space = [](char c){
        return c == '\r'
            || c == '\t'
            || c == '\n';
    };
    // replace \t with space and ignore multi-line
    for (auto* s = text.c_str(); *s; ++s) {
        if (is_special_space(*s)) {
            constexpr std::size_t buf_size = 255;
            char buf[buf_size + 1];
            auto* p = buf;
            auto* end = text.data() + std::min(buf_size, text.size());
            auto n = std::min(buf_size, std::size_t(s - text.data()));
            memcpy(p, text.data(), n);
            p += n;
            for (; s < end; ++s) {
                if (!is_special_space(*s)) {
                    *p++ = *s;
                }
                else if (*s == '\r' || *s == '\n') {
                    break;
                }
                else {
                    *p++ = ' ';
                }
            }
            *p = '\0';
            this->insert_text(buf);
            return ;
        }
    }

    this->insert_text(text.c_str());
}
