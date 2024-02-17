package com.axelor.sale.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FingerprintDto {
    private String format;
    private byte[] data;
}
