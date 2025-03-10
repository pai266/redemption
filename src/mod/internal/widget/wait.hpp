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
 *              Meng Tan, Jennifer Inthavong
 */

#pragma once

#include "utils/colors.hpp"
#include "mod/internal/widget/composite.hpp"
#include "mod/internal/widget/multiline.hpp"
#include "mod/internal/widget/group_box.hpp"
#include "mod/internal/widget/form.hpp"
#include "mod/internal/widget/button.hpp"

class WidgetWait : public WidgetComposite
{
public:
    struct Events
    {
        WidgetEventNotifier onaccept;
        WidgetEventNotifier onrefused;
        WidgetEventNotifier onconfirm;
        WidgetEventNotifier onctrl_shift;
    };

    WidgetWait(
        gdi::GraphicApi & drawable, CopyPaste & copy_paste, Rect const widget_rect,
        Events events, const char* caption, const char * text,
        WidgetButton * extra_button,
        Font const & font, Theme const & theme, Language lang,
        bool showform = false, unsigned flags = WidgetForm::NONE,
        std::chrono::minutes duration_max = std::chrono::minutes::zero()); /*NOLINT*/

    void move_size_widget(int16_t left, int16_t top, uint16_t width, uint16_t height);

    void rdp_input_scancode(KbdFlags flags, Scancode scancode, uint32_t event_time, Keymap const& keymap) override;

private:
    WidgetEventNotifier onaccept;
    WidgetEventNotifier onrefused;
    WidgetEventNotifier onctrl_shift;

    WidgetGroupBox groupbox;
    WidgetMultiLine dialog;

public:
    WidgetForm form;

private:
    WidgetButton goselector;

    WidgetButton   exit;
    WidgetButton * extra_button;

    bool hasform;
    bool hide_back_to_selector;
};
