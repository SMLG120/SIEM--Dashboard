package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.SiemAlert;

import java.util.List;

public record AlertDetail(
        SiemAlert alert,
        String assignedTo,
        List<AlertNote> notes
) {
}