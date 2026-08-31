/*
 * NVIDIA GeForce2 (NV15) 3D software rasterizer.
 *
 * Ported to QEMU from the Bochs Project's bx_geforce_c SVGA device
 * (Copyright (C) 2025-2026 The Bochs Project, LGPL v2+).  Only the NV15
 * (card_type 0x15) code path is retained.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include <math.h>
#include "geforce.h"
#include "geforce_pxextract.h"

#define BX_MAX(a, b) ((a) > (b) ? (a) : (b))
#define BX_MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef ALIGN
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#endif

/* ---- forward declarations (static functions) --------------------------- */

static bool d3d_scissor_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height);
static bool d3d_viewport_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height);
static bool d3d_window_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height);
static void d3d_clear_surface(NV15State *s, gf_channel *ch);
static void d3d_texture_process_format(NV15State *s, gf_texture *tex);
static void d3d_sample_texture(NV15State *s, gf_channel *ch,
  gf_texture *tex, float coords_in[3], float color[4]);
static void d3d_vertex_shader(NV15State *s, gf_channel *ch,
  float in[16][4], float out[16][4]);
static void d3d_register_combiners(NV15State *s, gf_channel *ch,
  float regs[16][4], float out[4]);
static bool d3d_pixel_shader(NV15State *s, gf_channel *ch,
  float in[16][4], float tmp_regs16[64][4], float tmp_regs32[64][4]);
static void d3d_triangle(NV15State *s, gf_channel *ch, uint32_t base);
static void d3d_clip_to_screen(NV15State *s, gf_channel *ch,
  float pos_clip[4], float pos_screen[4]);
static void d3d_triangle_clipped(NV15State *s, gf_channel *ch,
  float v0[16][4], float v1[16][4], float v2[16][4]);
static void d3d_process_vertex(NV15State *s, gf_channel *ch, bool immediate);
static void d3d_load_vertex(NV15State *s, gf_channel *ch, uint32_t index);
static uint32_t d3d_get_surface_pitch_z(NV15State *s, gf_channel *ch);

/* ---- free helper functions --------------------------------------------- */

static uint32_t swizzle(uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
  bool xleft = true;
  bool yleft = height != 1;
  uint32_t xbit = 1;
  uint32_t ybit = 1;
  uint32_t rbit = 1;
  uint32_t r = 0;
  do {
    if (xleft) {
      if ((x & xbit) != 0)
        r |= rbit;
      rbit <<= 1;
      xbit <<= 1;
      xleft = xbit < width;
    }
    if (yleft) {
      if ((y & ybit) != 0)
        r |= rbit;
      rbit <<= 1;
      ybit <<= 1;
      yleft = ybit < height;
    }
  } while (xleft || yleft);
  return r;
}

static double edge_function(const float *v0, const float *v1, const float *v2)
{
  return ((double)v1[0] - v0[0]) * ((double)v2[1] - v0[1]) -
         ((double)v1[1] - v0[1]) * ((double)v2[0] - v0[0]);
}

static float uint32_as_float(uint32_t val)
{
  union {
    uint32_t ui32;
    float f;
  } conv;
  conv.ui32 = val;
  return conv.f;
}

static void texture_update_size(gf_texture *tex, uint32_t cls)
{
  if (tex->linear || cls >= 0x4097) {
    tex->size[0] = tex->image_rect >> 16;
    tex->size[1] = tex->image_rect & 0x0000ffff;
  } else {
    tex->size[0] = 1 << tex->base_size[0];
    tex->size[1] = 1 << tex->base_size[1];
  }
  uint32_t lw = tex->size[0];
  uint32_t lh = tex->size[1];
  tex->face_bytes = 0;
  for (uint32_t i = 0; i < tex->levels; i++) {
    uint32_t level_bytes = lw * lh * tex->color_bytes;
    if (tex->compressed)
      level_bytes /= 16;
    tex->face_bytes += level_bytes;
    lw /= 2;
    lh /= 2;
    if (lw == 0)
      lw = 1;
    if (lh == 0)
      lh = 1;
  }
  tex->face_bytes = ALIGN(tex->face_bytes, 128);
}

static float dot3(float x[3], float y[3])
{
  return x[0] * y[0] + x[1] * y[1] + x[2] * y[2];
}

static float dot4(float x[4], float y[4])
{
  return x[0] * y[0] + x[1] * y[1] + x[2] * y[2] + x[3] * y[3];
}

static void reflection(float axis[3], float direction[3], float refl_dir[3])
{
  float k = 2.0f * dot3(axis, direction) / dot3(axis, axis);
  refl_dir[0] = k * axis[0] - direction[0];
  refl_dir[1] = k * axis[1] - direction[1];
  refl_dir[2] = k * axis[2] - direction[2];
}

static void dot_map(uint32_t func, float src[4], float dst[3])
{
  switch (func) {
    default:
    case 0:
      for (int ci = 0; ci < 3; ci++)
        dst[ci] = src[ci];
      break;
    case 1:
      for (int ci = 0; ci < 3; ci++)
        dst[ci] = (src[ci] * 255.0f - 128.0f) / 127.0f;
      break;
  }
}

static float dot3m(float x[3], float y[4], uint32_t map_func)
{
  float ym[3];
  dot_map(map_func, y, ym);
  return dot3(x, ym);
}

static float rc_get_var(uint32_t cw, uint32_t shift, float regs[16][4], uint32_t civ)
{
  uint32_t x = cw >> shift;
  uint32_t reg = x & 0xf;
  uint32_t pir = (x >> 4) & 1;
  uint32_t map = (x >> 5) & 7;
  uint32_t cir = (bool)pir ? 3 : civ;
  float value = regs[reg][cir];
  switch (map) {
    case 0: // UNSIGNED_IDENTITY
      return BX_MAX(0.0f, value);
    case 1: // UNSIGNED_INVERT
      return 1.0f - BX_MIN(BX_MAX(value, 0.0f), 1.0f);
    case 2: // EXPAND_NORMAL
      return 2.0f * BX_MAX(0.0f, value) - 1.0f;
    case 3: // EXPAND_NEGATE
      return -2.0f * BX_MAX(0.0f, value) + 1.0f;
    case 4: // HALF_BIAS_NORMAL
      return BX_MAX(0.0f, value) - 0.5f;
    case 5: // HALF_BIAS_NEGATE
      return -BX_MAX(0.0f, value) + 0.5f;
    default:
    case 6: // SIGNED_IDENTITY
      return value;
    case 7: // SIGNED_NEGATE
      return -value;
  }
}

static float length(float v[3])
{
  return sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
}

static float normalize(float v[3])
{
  float l = length(v);
  float scale = 1.0f / l;
  v[0] *= scale;
  v[1] *= scale;
  v[2] *= scale;
  return l;
}

static void normalize_to(float in[3], float out[3])
{
  float scale = 1.0f / length(in);
  out[0] = in[0] * scale;
  out[1] = in[1] * scale;
  out[2] = in[2] * scale;
}

/* p is a homogeneous 4-vector (callers pass a 4-element array); only the
 * first three transformed components are produced. */
static void position_to_view3(gf_channel *ch, float *p, float pt[3])
{
  float *m = ch->d3d_model_view_matrix[0];
  pt[0] = p[0] * m[0]  + p[1] * m[1]  + p[2] * m[2]  + p[3] * m[3];
  pt[1] = p[0] * m[4]  + p[1] * m[5]  + p[2] * m[6]  + p[3] * m[7];
  pt[2] = p[0] * m[8]  + p[1] * m[9]  + p[2] * m[10] + p[3] * m[11];
}

static void position_to_view4(gf_channel *ch, float p[4], float pt[4])
{
  float *m = ch->d3d_model_view_matrix[0];
  pt[0] = p[0] * m[0]  + p[1] * m[1]  + p[2] * m[2]  + p[3] * m[3];
  pt[1] = p[0] * m[4]  + p[1] * m[5]  + p[2] * m[6]  + p[3] * m[7];
  pt[2] = p[0] * m[8]  + p[1] * m[9]  + p[2] * m[10] + p[3] * m[11];
  pt[3] = p[0] * m[12] + p[1] * m[13] + p[2] * m[14] + p[3] * m[15];
}

static void normal_to_view(gf_channel *ch, float n[3], float nt[3])
{
  float *m = ch->d3d_inverse_model_view_matrix;
  nt[0] = n[0] * m[0] + n[1] * m[1] + n[2] * m[2];
  nt[1] = n[0] * m[4] + n[1] * m[5] + n[2] * m[6];
  nt[2] = n[0] * m[8] + n[1] * m[9] + n[2] * m[10];
  if (ch->d3d_normalize_enable)
    normalize(nt);
}

static float blend_equation(uint16_t equation, float src, float src_factor, float dst, float dst_factor)
{
  switch (equation) {
    case 0x0001: // ADD
    case 0x8006: // FUNC_ADD
    default:
      return src * src_factor + dst * dst_factor;
    case 0x0002: // SUBTRACT
    case 0x800a: // FUNC_SUBTRACT
      return src * src_factor - dst * dst_factor;
    case 0x0003: // REV_SUBTRACT
    case 0x800b: // FUNC_REVERSE_SUBTRACT
      return dst * dst_factor - src * src_factor;
    case 0x0004: // MIN
    case 0x8007: // MIN
      return BX_MIN(src, dst);
    case 0x0005: // MAX
    case 0x8008: // MAX
      return BX_MAX(src, dst);
  }
}

static float blend_factor(uint16_t factor, float src_rgb, float src_a,
                   float dst_rgb, float dst_a, float const_rgb, float const_a)
{
  switch (factor) {
    case 0x0000: // ZERO
    case 0x1001: // ZERO
      return 0.0f;
    case 0x0001: // ONE
    case 0x1002: // ONE
      return 1.0f;
    case 0x0300: // SRC_COLOR
    case 0x1003: // SRC_COLOR
      return src_rgb;
    case 0x0301: // ONE_MINUS_SRC_COLOR
    case 0x1004: // INV_SRC_COLOR
      return 1.0f - src_rgb;
    case 0x0302: // SRC_ALPHA
    case 0x1005: // SRC_ALPHA
      return src_a;
    case 0x0303: // ONE_MINUS_SRC_ALPHA
    case 0x1006: // INV_SRC_ALPHA
      return 1.0f - src_a;
    case 0x0304: // DST_ALPHA
    case 0x1007: // DEST_ALPHA
      return dst_a;
    case 0x0305: // ONE_MINUS_DST_ALPHA
    case 0x1008: // INV_DEST_ALPHA
      return 1.0f - dst_a;
    case 0x0306: // DST_COLOR
    case 0x1009: // DEST_COLOR
      return dst_rgb;
    case 0x0307: // ONE_MINUS_DST_COLOR
    case 0x100a: // INV_DEST_COLOR
      return 1.0f - dst_rgb;
    case 0x0308: // SRC_ALPHA_SATURATE
    case 0x100b: // SRC_ALPHA_SAT
      return BX_MIN(src_a, 1.0f - dst_a);
    case 0x8001: // CONSTANT_COLOR
    case 0x100e: // BLEND_FACTOR
      return const_rgb;
    case 0x8002: // ONE_MINUS_CONSTANT_COLOR
    case 0x100f: // INV_BLEND_FACTOR
      return 1.0f - const_rgb;
    case 0x8003: // CONSTANT_ALPHA
      return const_a;
    case 0x8004: // ONE_MINUS_CONSTANT_ALPHA
      return 1.0f - const_a;
    default:
      return 0.5f;
  }
}

static bool compare(uint32_t func, uint32_t val1, uint32_t val2)
{
  switch (func) {
    case 1:
    case 0x200: // NEVER
      return false;
    case 2:
    case 0x201: // LESS
    default:
      return val1 < val2;
    case 3:
    case 0x202: // EQUAL
      return val1 == val2;
    case 4:
    case 0x203: // LEQUAL
      return val1 <= val2;
    case 5:
    case 0x204: // GREATER
      return val1 > val2;
    case 6:
    case 0x205: // NOTEQUAL
      return val1 != val2;
    case 7:
    case 0x206: // GEQUAL
      return val1 >= val2;
    case 8:
    case 0x207: // ALWAYS
      return true;
  }
}

static void unpack_attribute(uint32_t value, bool d3d, float comp[4])
{
  if (d3d) {
    comp[0] = ((value >> (2 * 8)) & 0xff) / 255.0f;
    comp[1] = ((value >> (1 * 8)) & 0xff) / 255.0f;
    comp[2] = ((value >> (0 * 8)) & 0xff) / 255.0f;
    comp[3] = ((value >> (3 * 8)) & 0xff) / 255.0f;
  } else {
    for (uint32_t i = 0; i < 4; i++)
      comp[i] = ((value >> (i * 8)) & 0xff) / 255.0f;
  }
}

/* ---- d3d core algorithms ----------------------------------------------- */

static bool d3d_scissor_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height)
{
  if (s->card_type >= 0x35) {
    int32_t surf_x2 = *x + *width;
    int32_t surf_y2 = *y + *height;
    int32_t scissor_x1 = (int32_t)ch->d3d_scissor_x + ch->d3d_window_offset_x;
    int32_t scissor_y1 = (int32_t)ch->d3d_scissor_y + ch->d3d_window_offset_y;
    int32_t scissor_x2 = scissor_x1 + (int32_t)ch->d3d_scissor_width;
    int32_t scissor_y2 = scissor_y1 + (int32_t)ch->d3d_scissor_height;
    if (scissor_x1 >= surf_x2 || scissor_x2 <= (int32_t)*x ||
        scissor_y1 >= surf_y2 || scissor_y2 <= (int32_t)*y)
      return false;
    *x = BX_MAX((int32_t)*x, scissor_x1);
    *y = BX_MAX((int32_t)*y, scissor_y1);
    *width = BX_MIN(surf_x2, scissor_x2) - *x;
    *height = BX_MIN(surf_y2, scissor_y2) - *y;
  }
  return true;
}

static bool d3d_viewport_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height)
{
  if (s->card_type >= 0x35) {
    int32_t surf_x2 = *x + *width;
    int32_t surf_y2 = *y + *height;
    int32_t viewport_x1 = (int32_t)ch->d3d_viewport_x + ch->d3d_window_offset_x;
    int32_t viewport_y1 = (int32_t)ch->d3d_viewport_y + ch->d3d_window_offset_y;
    int32_t viewport_x2 = viewport_x1 + (int32_t)ch->d3d_viewport_width;
    int32_t viewport_y2 = viewport_y1 + (int32_t)ch->d3d_viewport_height;
    if (viewport_x1 >= surf_x2 || viewport_x2 <= (int32_t)*x ||
        viewport_y1 >= surf_y2 || viewport_y2 <= (int32_t)*y)
      return false;
    *x = BX_MAX((int32_t)*x, viewport_x1);
    *y = BX_MAX((int32_t)*y, viewport_y1);
    *width = BX_MIN(surf_x2, viewport_x2) - *x;
    *height = BX_MIN(surf_y2, viewport_y2) - *y;
  }
  return true;
}

static bool d3d_window_clip(NV15State *s, gf_channel *ch,
  uint32_t *x, uint32_t *y, uint32_t *width, uint32_t *height)
{
  if (s->card_type >= 0x35) {
    int32_t surf_x2 = *x + *width;
    int32_t surf_y2 = *y + *height;
    int32_t window_x1 = (int32_t)ch->d3d_window_clip_x1[0] + ch->d3d_window_offset_x;
    int32_t window_y1 = (int32_t)ch->d3d_window_clip_y1[0] + ch->d3d_window_offset_y;
    int32_t window_x2 = (int32_t)ch->d3d_window_clip_x2[0] + ch->d3d_window_offset_x + 1;
    int32_t window_y2 = (int32_t)ch->d3d_window_clip_y2[0] + ch->d3d_window_offset_y + 1;
    if (window_x1 >= surf_x2 || window_x2 <= (int32_t)*x ||
        window_y1 >= surf_y2 || window_y2 <= (int32_t)*y)
      return false;
    *x = BX_MAX((int32_t)*x, window_x1);
    *y = BX_MAX((int32_t)*y, window_y1);
    *width = BX_MIN(surf_x2, window_x2) - *x;
    *height = BX_MIN(surf_y2, window_y2) - *y;
  }
  return true;
}

static void d3d_clear_surface(NV15State *s, gf_channel *ch)
{
  uint32_t dx = ch->d3d_clip_horizontal & 0xFFFF;
  uint32_t dy = ch->d3d_clip_vertical & 0xFFFF;
  uint32_t width = ch->d3d_clip_horizontal >> 16;
  uint32_t height = ch->d3d_clip_vertical >> 16;
  if (!d3d_scissor_clip(s, ch, &dx, &dy, &width, &height))
    return;
  if (ch->d3d_clear_surface & 0x000000F0) {
    uint32_t pitch = ch->d3d_surface_pitch_a & 0xFFFF;
    uint32_t draw_offset = ch->d3d_surface_color_offset +
      dy * pitch + dx * ch->d3d_color_bytes;
    uint32_t redraw_offset = nv_dma_lin_lookup(s, ch->d3d_color_obj, draw_offset) -
      s->disp_offset;
    for (uint32_t y = 0; y < height; y++) {
      for (uint32_t x = 0; x < width; x++) {
        if (ch->d3d_color_bytes == 2)
          nv_dma_write16(s, ch->d3d_color_obj, draw_offset + x * 2, ch->d3d_color_clear_value);
        else
          nv_dma_write32(s, ch->d3d_color_obj, draw_offset + x * 4, ch->d3d_color_clear_value);
      }
      draw_offset += pitch;
    }
    nv_redraw_area_nd_off(s, redraw_offset, width, height);
  }
  bool depth_clear = (ch->d3d_clear_surface & 0x00000001) != 0;
  bool stencil_clear = (ch->d3d_clear_surface & 0x00000002) != 0;
  if (depth_clear || stencil_clear) {
    uint32_t pitch = d3d_get_surface_pitch_z(s, ch);
    uint32_t draw_offset = ch->d3d_surface_zeta_offset +
      dy * pitch + dx * ch->d3d_depth_bytes;
    for (uint32_t y = 0; y < height; y++) {
      for (uint32_t x = 0; x < width; x++) {
        if (ch->d3d_depth_bytes == 2) {
          if (depth_clear)
            nv_dma_write16(s, ch->d3d_zeta_obj, draw_offset + x * 2, ch->d3d_zstencil_clear_value);
        } else {
          if (depth_clear) {
            if (stencil_clear)
              nv_dma_write32(s, ch->d3d_zeta_obj, draw_offset + x * 4, ch->d3d_zstencil_clear_value);
            else {
              nv_dma_write8(s, ch->d3d_zeta_obj, draw_offset + x * 4 + 1, (uint8_t)(ch->d3d_zstencil_clear_value >> 8));
              nv_dma_write16(s, ch->d3d_zeta_obj, draw_offset + x * 4 + 2, (uint16_t)(ch->d3d_zstencil_clear_value >> 16));
            }
          } else
            nv_dma_write8(s, ch->d3d_zeta_obj, draw_offset + x * 4, (uint8_t)ch->d3d_zstencil_clear_value);
        }
      }
      draw_offset += pitch;
    }
  }
}

static void d3d_texture_process_format(NV15State *s, gf_texture *tex)
{
  static bool unknown_format_reported = false;

  tex->linear = false;
  tex->unnormalized = false;
  tex->compressed = false;
  tex->dxt_alpha_data = false;
  tex->dxt_alpha_explicit = false;
  if ((tex->format & 0x80) != 0) {
    if ((tex->format & 0x20) != 0)
      tex->linear = true;
    if ((tex->format & 0x40) != 0)
      tex->unnormalized = true;
    tex->format &= 0x9f;
  } else if (tex->format == 0x12 ||
             tex->format == 0x1b ||
             tex->format == 0x1e) {
    tex->linear = true;
    tex->unnormalized = true;
  }
  switch (tex->format) {
    case 0x0c: // DXT1
    case 0x0e: // DXT23
    case 0x0f: // DXT45
    case 0x86: // DXT1
    case 0x87: // DXT23
    case 0x88: // DXT45
      tex->compressed = true;
      tex->dxt_alpha_data = tex->format != 0x0c && tex->format != 0x86;
      tex->dxt_alpha_explicit = tex->format == 0x0e || tex->format == 0x87;
      tex->color_bytes = tex->dxt_alpha_data ? 16 : 8;
      break;
    case 0x02: // A1R5G5B5
    case 0x03: // X1R5G5B5
    case 0x04: // A4R4G4B4
    case 0x05: // R5G6B5
    case 0x27: // R6G5B5
    case 0x28: // G8B8
    case 0x82: // A1R5G5B5
    case 0x83: // A4R4G4B4
    case 0x84: // R5G6B5
    case 0x8b: // G8B8
    case 0x8f: // R6G5B5
      tex->color_bytes = 2;
      break;
    case 0x06: // A8R8G8B8
    case 0x07: // X8R8G8B8
    case 0x12: // A8R8G8B8
    case 0x1e: // X8R8G8B8
    case 0x3a: // A8B8G8R8
    case 0x85: // A8R8G8B8
      tex->color_bytes = 4;
      break;
    default:
      if (!unknown_format_reported) {
        unknown_format_reported = true;
      }
      // fallthrough
    case 0x00: // Y8
    case 0x01: // AY8
    case 0x0b: // I8_A8R8G8B8
    case 0x1b: // AY8
    case 0x81: // B8
      tex->color_bytes = 1;
      break;
  }
}

static void d3d_sample_texture(NV15State *s, gf_channel *ch,
  gf_texture *tex, float coords_in[3], float color[4])
{
  float *coords;
  float coords_cubemap[3];
  uint32_t tex_ofs = tex->offset;
  if (tex->cubemap) {
    uint32_t face;
    float coords_abs[3];
    for (uint32_t i = 0; i < 3; i++)
      coords_abs[i] = fabs(coords_in[i]);
    if (coords_abs[0] > coords_abs[1] && coords_abs[0] > coords_abs[2]) {
      coords_cubemap[0] = coords_cubemap[1] = 1.0f / coords_abs[0];
      if (coords_in[0] > 0.0f) {
        face = 0;
        coords_cubemap[0] *= -coords_in[2];
        coords_cubemap[1] *= -coords_in[1];
      } else {
        face = 1;
        coords_cubemap[0] *= coords_in[2];
        coords_cubemap[1] *= -coords_in[1];
      }
    } else if (coords_abs[1] > coords_abs[0] && coords_abs[1] > coords_abs[2]) {
      coords_cubemap[0] = coords_cubemap[1] = 1.0f / coords_abs[1];
      if (coords_in[1] > 0.0f) {
        face = 2;
        coords_cubemap[0] *= coords_in[0];
        coords_cubemap[1] *= coords_in[2];
      } else {
        face = 3;
        coords_cubemap[0] *= coords_in[0];
        coords_cubemap[1] *= -coords_in[2];
      }
    } else {
      coords_cubemap[0] = coords_cubemap[1] = 1.0f / coords_abs[2];
      if (coords_in[2] > 0.0f) {
        face = 4;
        coords_cubemap[0] *= coords_in[0];
        coords_cubemap[1] *= -coords_in[1];
      } else {
        face = 5;
        coords_cubemap[0] *= -coords_in[0];
        coords_cubemap[1] *= -coords_in[1];
      }
    }
    coords_cubemap[0] = (coords_cubemap[0] + 1.0f) * 0.5f;
    coords_cubemap[1] = (coords_cubemap[1] + 1.0f) * 0.5f;
    coords_cubemap[2] = 0.0f;
    coords = coords_cubemap;
    tex_ofs += face * tex->face_bytes;
  } else {
    coords = coords_in;
  }
  uint32_t xy[2];
  for (int i = 0; i < 2; i++) {
    if (tex->unnormalized) {
      int32_t c = coords[i];
      uint32_t size = tex->size[i];
      if (c < 0 || (uint32_t)c >= size) {
        switch (tex->wrap[i]) {
          case 1:  // WRAP
            c %= size;
            if (c < 0)
              c += size;
            break;
          case 2:  // MIRROR
            c %= size * 2;
            if (c < 0)
              c += size * 2;
            if ((uint32_t)c >= size)
              c = size * 2 - c - 1;
            break;
          default: // CLAMP_TO_EDGE
            c = c < 0 ? 0 : size - 1;
            break;
        }
      }
      xy[i] = c;
    } else {
      float c = coords[i];
      if (c < 0.0f || c > 1.0f) {
        switch (tex->wrap[i]) {
          case 1:  // WRAP
            c = c - floor(c);
            break;
          case 2:  // MIRROR
            c = fmod(c, 2.0f);
            if (c < 0.0f)
              c += 2.0f;
            if (c > 1.0f)
              c = 2.0f - c;
            break;
          default: // CLAMP_TO_EDGE
            c = c < 0.0f ? 0.0f : 1.0f;
            break;
        }
      }
      xy[i] = c == 1.0f ? tex->size[i] - 1 : c * tex->size[i];
    }
  }
  if (tex->compressed) {
    uint32_t pitch = tex->size[0] * (tex->dxt_alpha_data ? 4 : 2);
    uint32_t bx = xy[0] >> 2;
    uint32_t by = xy[1] >> 2;
    tex_ofs += by * pitch + bx * tex->color_bytes;
  } else if (tex->linear) {
    uint32_t pitch;
    if (s->card_type >= 0x40)
      pitch = tex->control3 & 0x000fffff;
    else
      pitch = tex->control1 >> 16;
    tex_ofs += xy[1] * pitch + xy[0] * tex->color_bytes;
  } else
    tex_ofs += swizzle(xy[0], xy[1], tex->size[0], tex->size[1]) * tex->color_bytes;
  int32_t color_int[4];
  float color_scale[4];
  switch (tex->format) {
    case 0x0c:   // DXT1
    case 0x0e:   // DXT23
    case 0x0f:   // DXT45
    case 0x86:   // DXT1
    case 0x87:   // DXT23
    case 0x88: { // DXT45
      uint32_t ox = xy[0] & 3;
      uint32_t oy = xy[1] & 3;
      if (tex->dxt_alpha_data) {
        uint64_t alpha_word = nv_dma_read64(s, tex->dma_obj, tex_ofs);
        if (tex->dxt_alpha_explicit) {
          color_int[0] = (alpha_word >> (oy * 16 + ox * 4)) & 0xf;
          color_scale[0] = 1.0f / 15.0f;
        } else {
          uint32_t alpha_index = (alpha_word >> (16 + oy * 12 + ox * 3)) & 7;
          switch (alpha_index) {
            case 0: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              color_int[0] = alpha0;
              color_scale[0] = 1.0f / 255.0f;
              break;
            }
            case 1: {
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              color_int[0] = alpha1;
              color_scale[0] = 1.0f / 255.0f;
              break;
            }
            case 2: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = 6 * alpha0 + alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = 4 * alpha0 + alpha1;
                color_scale[0] = 1.0f / 1275.0f;
              }
              break;
            }
            case 3: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = 5 * alpha0 + 2 * alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = 3 * alpha0 + 2 * alpha1;
                color_scale[0] = 1.0f / 1275.0f;
              }
              break;
            }
            case 4: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = 4 * alpha0 + 3 * alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = 2 * alpha0 + 3 * alpha1;
                color_scale[0] = 1.0f / 1275.0f;
              }
              break;
            }
            case 5: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = 3 * alpha0 + 4 * alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = alpha0 + 4 * alpha1;
                color_scale[0] = 1.0f / 1275.0f;
              }
              break;
            }
            case 6: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = 2 * alpha0 + 5 * alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = 0;
                color_scale[0] = 1.0f;
              }
              break;
            }
            case 7: {
              uint8_t alpha0 = (uint8_t)alpha_word;
              uint8_t alpha1 = (uint8_t)(alpha_word >> 8);
              if (alpha0 > alpha1) {
                color_int[0] = alpha0 + 6 * alpha1;
                color_scale[0] = 1.0f / 1785.0f;
              } else {
                color_int[0] = 1;
                color_scale[0] = 1.0f;
              }
              break;
            }
          }
        }
      } else {
        color_int[0] = 1;
        color_scale[0] = 1.0f;
      }
      uint64_t color_word = nv_dma_read64(s, tex->dma_obj, tex_ofs + (tex->dxt_alpha_data ? 8 : 0));
      uint32_t color_index = (color_word >> (32 + oy * 8 + ox * 2)) & 3;
      switch (color_index) {
        case 0: {
          uint16_t color0 = (uint16_t)color_word;
          color_int[1] = (color0 >> 11) & 0x1f;
          color_scale[1] = 1.0f / 31.0f;
          color_int[2] = (color0 >> 5) & 0x3f;
          color_scale[2] = 1.0f / 63.0f;
          color_int[3] = (color0 >> 0) & 0x1f;
          color_scale[3] = 1.0f / 31.0f;
          break;
        }
        case 1: {
          uint16_t color1 = (uint16_t)(color_word >> 16);
          color_int[1] = (color1 >> 11) & 0x1f;
          color_scale[1] = 1.0f / 31.0f;
          color_int[2] = (color1 >> 5) & 0x3f;
          color_scale[2] = 1.0f / 63.0f;
          color_int[3] = (color1 >> 0) & 0x1f;
          color_scale[3] = 1.0f / 31.0f;
          break;
        }
        case 2: {
          uint16_t color0 = (uint16_t)color_word;
          uint16_t color1 = (uint16_t)(color_word >> 16);
          if (color0 > color1) {
            color_int[1] = 2 * ((color0 >> 11) & 0x1f) + ((color1 >> 11) & 0x1f);
            color_scale[1] = 1.0f / 93.0f;
            color_int[2] = 2 * ((color0 >> 5) & 0x3f) + ((color1 >> 5) & 0x3f);
            color_scale[2] = 1.0f / 189.0f;
            color_int[3] = 2 * ((color0 >> 0) & 0x1f) + ((color1 >> 0) & 0x1f);
            color_scale[3] = 1.0f / 93.0f;
          } else {
            color_int[1] = ((color0 >> 11) & 0x1f) + ((color1 >> 11) & 0x1f);
            color_scale[1] = 1.0f / 62.0f;
            color_int[2] = ((color0 >> 5) & 0x3f) + ((color1 >> 5) & 0x3f);
            color_scale[2] = 1.0f / 126.0f;
            color_int[3] = ((color0 >> 0) & 0x1f) + ((color1 >> 0) & 0x1f);
            color_scale[3] = 1.0f / 62.0f;
          }
          break;
        }
        case 3: {
          uint16_t color0 = (uint16_t)color_word;
          uint16_t color1 = (uint16_t)(color_word >> 16);
          if (color0 > color1) {
            color_int[1] = 2 * ((color1 >> 11) & 0x1f) + ((color0 >> 11) & 0x1f);
            color_scale[1] = 1.0f / 93.0f;
            color_int[2] = 2 * ((color1 >> 5) & 0x3f) + ((color0 >> 5) & 0x3f);
            color_scale[2] = 1.0f / 189.0f;
            color_int[3] = 2 * ((color1 >> 0) & 0x1f) + ((color0 >> 0) & 0x1f);
            color_scale[3] = 1.0f / 93.0f;
          } else {
            color_int[0] = 0;
            color_scale[0] = 1.0f;
            color_int[1] = 0;
            color_scale[1] = 1.0f;
            color_int[2] = 0;
            color_scale[2] = 1.0f;
            color_int[3] = 0;
            color_scale[3] = 1.0f;
          }
          break;
        }
      }
      break;
    }
    case 0x04:
    case 0x83: { // A4R4G4B4
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      color_int[0] = (value >> 12) & 0xf;
      color_scale[0] = 1.0f / 15.0f;
      color_int[1] = (value >> 8) & 0xf;
      color_scale[1] = 1.0f / 15.0f;
      color_int[2] = (value >> 4) & 0xf;
      color_scale[2] = 1.0f / 15.0f;
      color_int[3] = (value >> 0) & 0xf;
      color_scale[3] = 1.0f / 15.0f;
      break;
    }
    case 0x05:
    case 0x84: { // R5G6B5
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = (value >> 11) & 0x1f;
      color_scale[1] = 1.0f / 31.0f;
      color_int[2] = (value >> 5) & 0x3f;
      color_scale[2] = 1.0f / 63.0f;
      color_int[3] = (value >> 0) & 0x1f;
      color_scale[3] = 1.0f / 31.0f;
      break;
    }
    case 0x02:
    case 0x82: { // A1R5G5B5
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      if ((tex->control0 & 3) != 0 && value == tex->key_color) {
        color_int[0] = 0;
      } else {
        color_int[0] = (value >> 15) & 1;
      }
      color_scale[0] = 1.0f;
      color_int[1] = (value >> 10) & 0x1f;
      color_scale[1] = 1.0f / 31.0f;
      color_int[2] = (value >> 5) & 0x1f;
      color_scale[2] = 1.0f / 31.0f;
      color_int[3] = (value >> 0) & 0x1f;
      color_scale[3] = 1.0f / 31.0f;
      break;
    }
    case 0x03: { // X1R5G5B5
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = (value >> 10) & 0x1f;
      color_scale[1] = 1.0f / 31.0f;
      color_int[2] = (value >> 5) & 0x1f;
      color_scale[2] = 1.0f / 31.0f;
      color_int[3] = (value >> 0) & 0x1f;
      color_scale[3] = 1.0f / 31.0f;
      break;
    }
    case 0x27:
    case 0x8f: { // R6G5B5
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = (value >> 10) & 0x3f;
      color_scale[1] = 1.0f / 63.0f;
      color_int[2] = (value >> 5) & 0x1f;
      color_scale[2] = 1.0f / 31.0f;
      color_int[3] = (value >> 0) & 0x1f;
      color_scale[3] = 1.0f / 31.0f;
      break;
    }
    case 0x28:
    case 0x8b: { // G8B8
      uint16_t value = nv_dma_read16(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = 1;
      color_scale[1] = 1.0f;
      color_int[2] = (value >> 8) & 0xff;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = (value >> 0) & 0xff;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x06:
    case 0x12:
    case 0x85: { // A8R8G8B8
      uint32_t value = nv_dma_read32(s, tex->dma_obj, tex_ofs);
      color_int[0] = (value >> 24) & 0xff;
      color_scale[0] = 1.0f / 255.0f;
      color_int[1] = (value >> 16) & 0xff;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = (value >> 8) & 0xff;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = (value >> 0) & 0xff;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x3a: { // A8B8G8R8
      uint32_t value = nv_dma_read32(s, tex->dma_obj, tex_ofs);
      color_int[0] = (value >> 24) & 0xff;
      color_scale[0] = 1.0f / 255.0f;
      color_int[1] = (value >> 0) & 0xff;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = (value >> 8) & 0xff;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = (value >> 16) & 0xff;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x07:
    case 0x1e: { // X8R8G8B8
      uint32_t value = nv_dma_read32(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = (value >> 16) & 0xff;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = (value >> 8) & 0xff;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = (value >> 0) & 0xff;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x0b: { // I8_A8R8G8B8
      uint32_t pal_index = nv_dma_read8(s, tex->dma_obj, tex_ofs);
      uint32_t value = nv_dma_read32(s, tex->pal_dma_obj, tex->pal_ofs + pal_index * 4);
      color_int[0] = (value >> 24) & 0xff;
      color_scale[0] = 1.0f / 255.0f;
      color_int[1] = (value >> 16) & 0xff;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = (value >> 8) & 0xff;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = (value >> 0) & 0xff;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x00:   // Y8
    case 0x81: { // B8
      uint8_t value = nv_dma_read8(s, tex->dma_obj, tex_ofs);
      color_int[0] = 1;
      color_scale[0] = 1.0f;
      color_int[1] = value;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = value;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = value;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    case 0x01:
    case 0x1b: { // AY8
      uint8_t value = nv_dma_read8(s, tex->dma_obj, tex_ofs);
      color_int[0] = value;
      color_scale[0] = 1.0f / 255.0f;
      color_int[1] = value;
      color_scale[1] = 1.0f / 255.0f;
      color_int[2] = value;
      color_scale[2] = 1.0f / 255.0f;
      color_int[3] = value;
      color_scale[3] = 1.0f / 255.0f;
      break;
    }
    default:
      color_int[0] = 1;
      color_scale[0] = 0.8f;
      color_int[1] = 1;
      color_scale[1] = 0.8f + coords[0] * 0.2f;
      color_int[2] = 1;
      color_scale[2] = 0.6f + coords[1] * 0.2f;
      color_int[3] = 1;
      color_scale[3] = 0.6f + coords[2] * 0.2f;
      break;
  }
  if (tex->signed_any) {
    for (uint32_t i = 0; i < 4; i++)
      if (tex->signed_comp[i]) {
        color_int[i] = (int8_t)color_int[i];
        color_scale[i] = 1.0f / 128.0f;
      }
  }
  if (s->card_type <= 0x20) {
    for (uint32_t i = 0; i < 4; i++) {
      uint32_t j = (i + 3) & 3;
      color[j] = color_int[i] * color_scale[i];
    }
  } else {
    uint16_t s01 = tex->control1;
    for (uint32_t i = 0; i < 4; i++) {
      uint32_t j = (i + 3) & 3;
      switch ((s01 >> (8 + i * 2)) & 3) {
        case 0:
          color[j] = 0.0f;
          break;
        case 1:
          color[j] = 1.0f;
          break;
        default: {
          uint32_t swz = (s01 >> (i * 2)) & 3;
          color[j] = color_int[swz] * color_scale[swz];
          break;
        }
      }
    }
  }
}

static void d3d_vertex_shader(NV15State *s, gf_channel *ch, float in[16][4], float out[16][4])
{
  static bool unknown_opcode_reported = false;
  for (int a = 0; a < 16; a++) {
    out[a][0] = 0.0f;
    out[a][1] = 0.0f;
    out[a][2] = 0.0f;
    out[a][3] = 1.0f;
  }
  int32_t addr_regs[2][4] = { { 0 } };
  float tmp_regs[32][4];
  for (uint32_t r = 0; r < ch->d3d_vs_temp_regs_count; r++)
    for (uint32_t ci = 0; ci < 4; ci++)
      tmp_regs[r][ci] = 0.0f;
  for (uint32_t op_index = ch->d3d_transform_program_start;
       op_index < 544; op_index++) {
    uint32_t *tokens = ch->d3d_transform_program[op_index];
    float params[3][4];
    for (int p = 0; p < 3; p++) {
      uint32_t tmp_index;
      uint32_t reg_type;
      bool absolute = false;
      bool negate;
      uint32_t swizzle[4];
      if (p == 0) {
        if (s->card_type >= 0x35)
          absolute = (tokens[0] >> 21) & 1;
        if (s->card_type <= 0x35) {
          reg_type = (tokens[2] >> 26) & 3;
          tmp_index = (tokens[2] >> 28) & 0xf;
          negate = (tokens[1] >> 8) & 1;
          for (int i = 0; i < 4; i++)
            swizzle[i] = (tokens[1] >> (6 - i * 2)) & 3;
        } else {
          reg_type = (tokens[2] >> 23) & 3;
          tmp_index = (tokens[2] >> 25) & 0x3f;
          swizzle[3] = ((tokens[1] & 1) << 1) | ((tokens[2] >> 31) & 1);
          swizzle[2] = (tokens[1] >> 1) & 3;
          swizzle[1] = (tokens[1] >> 3) & 3;
          swizzle[0] = (tokens[1] >> 5) & 3;
          negate = (tokens[1] >> 7) & 1;
        }
      } else if (p == 1) {
        if (s->card_type >= 0x35)
          absolute = (tokens[0] >> 22) & 1;
        if (s->card_type <= 0x35) {
          reg_type = (tokens[2] >> 11) & 3;
          tmp_index = (tokens[2] >> 13) & 0xf;
          negate = (tokens[2] >> 25) & 1;
          for (int i = 0; i < 4; i++)
            swizzle[i] = (tokens[2] >> (23 - i * 2)) & 3;
        } else {
          reg_type = (tokens[2] >> 6) & 3;
          tmp_index = (tokens[2] >> 8) & 0x3f;
          for (int i = 0; i < 4; i++)
            swizzle[i] = (tokens[2] >> (20 - i * 2)) & 3;
          negate = (tokens[2] >> 22) & 1;
        }
      } else if (p == 2) {
        if (s->card_type >= 0x35)
          absolute = (tokens[0] >> 23) & 1;
        if (s->card_type <= 0x35) {
          reg_type = (tokens[3] >> 28) & 3;
          tmp_index = ((tokens[2] & 3) << 2) | ((tokens[3] >> 30) & 3);
          negate = (tokens[2] >> 10) & 1;
          for (int i = 0; i < 4; i++)
            swizzle[i] = (tokens[2] >> (8 - i * 2)) & 3;
        } else {
          reg_type = (tokens[3] >> 21) & 3;
          tmp_index = (tokens[3] >> 23) & 0x3f;
          swizzle[3] = (tokens[3] >> 29) & 3;
          swizzle[2] = ((tokens[2] & 1) << 1) | ((tokens[3] >> 31) & 1);
          swizzle[1] = (tokens[2] >> 1) & 3;
          swizzle[0] = (tokens[2] >> 3) & 3;
          negate = (tokens[2] >> 5) & 1;
        }
      }
      for (int comp_index = 0; comp_index < 4; comp_index++) {
        int comp_index_swizzle = swizzle[comp_index];
        if (reg_type == 1) {
          if (s->card_type == 0x20 && tmp_index == 12)
            params[p][comp_index] = out[0][comp_index_swizzle];
          else
            params[p][comp_index] = tmp_regs[tmp_index][comp_index_swizzle];
        } else if (reg_type == 2) {
          uint32_t in_index;
          if (s->card_type <= 0x35)
            in_index = (tokens[1] >> 9) & 0xf;
          else
            in_index = (tokens[1] >> 8) & 0xf;
          params[p][comp_index] = in[in_index][comp_index_swizzle];
        } else if (reg_type == 3) {
          uint32_t const_index;
          if (s->card_type == 0x20)
            const_index = (tokens[1] >> 13) & 0xff;
          else if (s->card_type == 0x35)
            const_index = (tokens[1] >> 14) & 0x1ff;
          else
            const_index = (tokens[1] >> 12) & 0x1ff;
          if (((tokens[3] >> 1) & 1) != 0) {
            uint32_t addr_reg_sel;
            uint32_t addr_swz;
            if (s->card_type == 0x20) {
              addr_reg_sel = 0;
              addr_swz = 0;
            } else {
              addr_reg_sel = (tokens[0] >> 24) & 1;
              if (s->card_type == 0x35)
                addr_swz = (tokens[0] >> 1) & 3;
              else
                addr_swz = tokens[0] & 3;
            }
            const_index = (const_index + addr_regs[addr_reg_sel][addr_swz]) & 0x1ff;
          }
          params[p][comp_index] = ch->d3d_transform_constant[const_index][comp_index_swizzle];
        }
        if (absolute)
          params[p][comp_index] = fabs(params[p][comp_index]);
        if (negate)
          params[p][comp_index] = -params[p][comp_index];
      }
    }
    uint32_t vec_op;
    if (s->card_type == 0x20)
      vec_op = (tokens[1] >> 21) & 0xf;
    else if (s->card_type == 0x35)
      vec_op = (tokens[1] >> 23) & 0x1f;
    else
      vec_op = (tokens[1] >> 22) & 0x1f;
    bool addr_write = false;
    float vec_result[4];
    switch (vec_op) {
      case 0: // NOP
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = 0.0f;
        break;
      case 1: // MOV
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index];
        break;
      case 2: // MUL
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] * params[1][comp_index];
        break;
      case 3: // ADD
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] + params[2][comp_index];
        break;
      case 4: // MAD
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          vec_result[comp_index] = params[0][comp_index] * params[1][comp_index] +
            params[2][comp_index];
        }
        break;
      case 5: { // DP3
        float dp3 = dot3(params[0], params[1]);
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = dp3;
        break;
      }
      case 6: { // DPH
        float dph = dot3(params[0], params[1]) + params[1][3];
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = dph;
        break;
      }
      case 7: { // DP4
        float dp4 = dot4(params[0], params[1]);
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = dp4;
        break;
      }
      case 8: // DST
        vec_result[0] = 1.0f;
        vec_result[1] = params[0][1] * params[1][1];
        vec_result[2] = params[0][2];
        vec_result[3] = params[1][3];
        break;
      case 9: // MIN
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = BX_MIN(params[0][comp_index], params[1][comp_index]);
        break;
      case 0xa: // MAX
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = BX_MAX(params[0][comp_index], params[1][comp_index]);
        break;
      case 0xb: // SLT
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] < params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0xc: // SGE
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] >= params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0xd: // ARL
        addr_write = true;
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = floor(params[0][comp_index]);
        break;
      case 0xe: // FRC
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] - floor(params[0][comp_index]);
        break;
      case 0xf: // FLR
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = floor(params[0][comp_index]);
        break;
      case 0x10: // SEQ
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] == params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0x11: // SFL
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = 0.0f;
        break;
      case 0x12: // SGT
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] > params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0x13: // SLE
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] <= params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0x14: // SNE
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = params[0][comp_index] != params[1][comp_index] ? 1.0f : 0.0f;
        break;
      case 0x15: // STR
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = 1.0f;
        break;
      case 0x16: // SSG
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          vec_result[comp_index] = params[0][comp_index] == 0.0f ? 0.0f :
            params[0][comp_index] < 0.0f ? -1.0f : 1.0f;
        }
        break;
      default:
        for (int comp_index = 0; comp_index < 4; comp_index++)
          vec_result[comp_index] = 0.5f;
        if (!unknown_opcode_reported) {
          unknown_opcode_reported = true;
        }
        break;
    }
    uint32_t sca_op;
    if (s->card_type == 0x20)
      sca_op = (tokens[1] >> 25) & 7;
    else if (s->card_type == 0x35)
      sca_op = ((tokens[0] & 1) << 4) | ((tokens[1] >> 28) & 0x0f);
    else
      sca_op = (tokens[1] >> 27) & 0x1f;
    bool paired_ops = vec_op != 0 && sca_op != 0;
    float sca_result[4];
    switch (sca_op) {
      case 0: // NOP
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = 0.0f;
        break;
      case 1: // MOV
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = params[2][comp_index];
        break;
      case 2: // RCP
      case 3: { // RCC
        float rcp = 1.0f / params[2][0];
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = rcp;
        break;
      }
      case 4: { // RSQ
        float rsq = 1.0f / sqrt(fabs(params[2][0]));
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = rsq;
        break;
      }
      case 5: { // EXP
        float fl = floor(params[2][0]);
        sca_result[0] = exp2(fl);
        sca_result[1] = params[2][0] - fl;
        sca_result[2] = exp2(params[2][0]);
        sca_result[3] = 1.0f;
        break;
      }
      case 6: { // LOG
        float fa = fabs(params[2][0]);
        if (fa != 0.0f) {
          if (isinf(fa)) {
            sca_result[0] = INFINITY;
            sca_result[1] = 1.0f;
            sca_result[2] = INFINITY;
          } else {
            sca_result[0] = floor(log2(fa));
            sca_result[1] = fa / exp2(floor(log2(fa)));
            sca_result[2] = log2(fa);
          }
        } else {
          sca_result[0] = -INFINITY;
          sca_result[1] = 1.0f;
          sca_result[2] = -INFINITY;
        }
        sca_result[3] = 1.0f;
        break;
      }
      case 7: { // LIT
        float tmpx = params[2][0];
        float tmpy = params[2][1];
        float tmpw = params[2][3];
        if (tmpx < 0.0f)
          tmpx = 0.0f;
        if (tmpy < 0.0f)
          tmpy = 0.0f;
        float epsilon = 1.0e-6f;
        if (tmpw < -(128.0f - epsilon))
          tmpw = -(128.0f - epsilon);
        else if (tmpw > 128.0f - epsilon)
          tmpw = 128.0f - epsilon;
        sca_result[0] = 1.0f;
        sca_result[1] = tmpx;
        sca_result[2] = (tmpx > 0.0f) ? pow(tmpy, tmpw) : 0.0f;
        sca_result[3] = 1.0f;
        break;
      }
      case 0xd: { // LG2
        float lg2 = log2(params[2][0]);
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = lg2;
        break;
      }
      case 0xe: { // EX2
        float ex2 = exp2(params[2][0]);
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = ex2;
        break;
      }
      default:
        for (int comp_index = 0; comp_index < 4; comp_index++)
          sca_result[comp_index] = 0.5f;
        if (!unknown_opcode_reported) {
          unknown_opcode_reported = true;
        }
        break;
    }
    if (s->card_type == 0x20) {
      uint32_t dst_out_reg = (tokens[3] >> 3) & 0xf;
      uint32_t dst_vec_mask = (tokens[3] >> 24) & 0xf;
      uint32_t dst_sca_mask = (tokens[3] >> 16) & 0xf;
      uint32_t dst_out_mask = (tokens[3] >> 12) & 0xf;
      uint32_t dst_tmp_reg = (tokens[3] >> 20) & 0xf;
      bool dst_out_sca = (tokens[3] >> 2) & 1;
      for (int comp_index = 0; comp_index < 4; comp_index++) {
        if (addr_write) {
          if (comp_index == 0)
            addr_regs[0][0] = (int32_t)vec_result[0];
        } else if ((dst_vec_mask & (8 >> comp_index)) != 0)
          tmp_regs[dst_tmp_reg][comp_index] = vec_result[comp_index];
        if ((dst_sca_mask & (8 >> comp_index)) != 0)
          tmp_regs[paired_ops ? 1 : dst_tmp_reg][comp_index] = sca_result[comp_index];
        if ((dst_out_mask & (8 >> comp_index)) != 0) {
          out[dst_out_reg][comp_index] = dst_out_sca ?
            sca_result[comp_index] : vec_result[comp_index];
        }
      }
    } else if (s->card_type == 0x35) {
      uint32_t dst_out_reg = (tokens[3] >> 2) & 0x1f;
      uint32_t dst_tmp_reg = (tokens[0] >> 16) & 0xf;
      uint32_t dst_vec_out_mask = (tokens[3] >> 12) & 0xf;
      uint32_t dst_sca_out_mask = (tokens[3] >> 16) & 0xf;
      uint32_t dst_vec_tmp_mask = (tokens[3] >> 20) & 0xf;
      uint32_t dst_sca_tmp_mask = (tokens[3] >> 24) & 0xf;
      for (int comp_index = 0; comp_index < 4; comp_index++) {
        if (dst_out_reg != 0x1f) {
          bool sca_out = (dst_sca_out_mask & (8 >> comp_index)) != 0;
          bool vec_out = (dst_vec_out_mask & (8 >> comp_index)) != 0;
          if (sca_out)
            out[dst_out_reg][comp_index] = sca_result[comp_index];
          if (vec_out)
            out[sca_out ? 0 : dst_out_reg][comp_index] = vec_result[comp_index];
        }
        if (dst_tmp_reg != 0xf) {
          if ((dst_vec_tmp_mask & (8 >> comp_index)) != 0) {
            if (addr_write)
              addr_regs[dst_tmp_reg & 1][comp_index] = (int32_t)vec_result[comp_index];
            else
              tmp_regs[dst_tmp_reg][comp_index] = vec_result[comp_index];
          }
        }
        if ((dst_sca_tmp_mask & (8 >> comp_index)) != 0) {
          if (paired_ops)
            tmp_regs[1][comp_index] = sca_result[comp_index];
          else if (dst_tmp_reg != 0xf)
            tmp_regs[dst_tmp_reg][comp_index] = sca_result[comp_index];
        }
      }
    } else {
      uint32_t dst_out_reg = (tokens[3] >> 2) & 0x1f;
      uint32_t dst_vec_mask = (tokens[3] >> 13) & 0xf;
      uint32_t dst_sca_mask = (tokens[3] >> 17) & 0xf;
      uint32_t dst_tmp_vec = (tokens[0] >> 15) & 0x3f;
      uint32_t dst_tmp_sca = (tokens[3] >> 7) & 0x3f;
      bool dst_out_vec = (tokens[0] >> 30) & 1;
      for (int comp_index = 0; comp_index < 4; comp_index++) {
        if ((dst_vec_mask & (8 >> comp_index)) != 0) {
          if (dst_out_vec && dst_out_reg != 0x1f)
            out[dst_out_reg][comp_index] = vec_result[comp_index];
          if (dst_tmp_vec != 0x3f) {
            if (addr_write)
              addr_regs[dst_tmp_vec & 1][comp_index] = (int32_t)vec_result[comp_index];
            else
              tmp_regs[dst_tmp_vec][comp_index] = vec_result[comp_index];
          }
        }
        if ((dst_sca_mask & (8 >> comp_index)) != 0) {
          if (!dst_out_vec && dst_out_reg != 0x1f)
            out[dst_out_reg][comp_index] = sca_result[comp_index];
          if (dst_tmp_sca != 0x3f)
            tmp_regs[dst_tmp_sca][comp_index] = sca_result[comp_index];
        }
      }
    }
    if ((tokens[3] & 1) == 1)
      break;
  }
}

static void d3d_register_combiners(NV15State *s, gf_channel *ch, float regs[16][4], float out[4])
{
  for (uint32_t st = 0; st < ch->d3d_combiner_control_num_stages; st++) {
    uint32_t icws[2] = {
      ch->d3d_combiner_color_icw[st],
      ch->d3d_combiner_alpha_icw[st]
    };
    if (icws[0] == 0 && icws[1] == 0)
      continue;
    for (uint32_t ci = 0; ci < 4; ci++) {
      regs[1][ci] = ch->d3d_combiner_const_color[st][0][ci];
      regs[2][ci] = ch->d3d_combiner_const_color[st][1][ci];
    }
    float vars[4][4];
    for (uint32_t civ = 0; civ < 4; civ++) {
      uint32_t icw = icws[(uint32_t)(civ == 3)];
      vars[0][civ] = rc_get_var(icw, 24, regs, civ);
      vars[1][civ] = rc_get_var(icw, 16, regs, civ);
      vars[2][civ] = rc_get_var(icw, 8, regs, civ);
      vars[3][civ] = rc_get_var(icw, 0, regs, civ);
    }
    uint32_t color_ocw = ch->d3d_combiner_color_ocw[st];
    uint32_t color_cd = color_ocw & 0xf;
    uint32_t color_ab = (color_ocw >> 4) & 0xf;
    uint32_t color_muxsum = (color_ocw >> 8) & 0xf;
    bool color_cd_dot = (color_ocw & 0x00001000) != 0;
    bool color_ab_dot = (color_ocw & 0x00002000) != 0;
    if (color_ab != 0) {
      if (color_ab_dot) {
        float ab_dot = vars[0][0] * vars[1][0] +
          vars[0][1] * vars[1][1] + vars[0][2] * vars[1][2];
        for (uint32_t ci = 0; ci < 3; ci++)
          regs[color_ab][ci] = ab_dot;
      } else {
        for (uint32_t ci = 0; ci < 3; ci++)
          regs[color_ab][ci] = vars[0][ci] * vars[1][ci];
      }
    }
    if (color_cd != 0) {
      if (color_cd_dot) {
        float cd_dot = vars[2][0] * vars[3][0] +
          vars[2][1] * vars[3][1] + vars[2][2] * vars[3][2];
        for (uint32_t ci = 0; ci < 3; ci++)
          regs[color_cd][ci] = cd_dot;
      } else {
        for (uint32_t ci = 0; ci < 3; ci++)
          regs[color_cd][ci] = vars[2][ci] * vars[3][ci];
      }
    }
    if (color_muxsum != 0)
      for (uint32_t ci = 0; ci < 3; ci++)
        regs[color_muxsum][ci] = vars[0][ci] * vars[1][ci] + vars[2][ci] * vars[3][ci];
    uint32_t alpha_ocw = ch->d3d_combiner_alpha_ocw[st];
    uint32_t alpha_cd = alpha_ocw & 0xf;
    uint32_t alpha_ab = (alpha_ocw >> 4) & 0xf;
    uint32_t alpha_muxsum = (alpha_ocw >> 8) & 0xf;
    if (alpha_ab != 0)
      regs[alpha_ab][3] = vars[0][3] * vars[1][3];
    if (alpha_cd != 0)
      regs[alpha_cd][3] = vars[2][3] * vars[3][3];
    if (alpha_muxsum != 0)
      regs[alpha_muxsum][3] = vars[0][3] * vars[1][3] + vars[2][3] * vars[3][3];
  }
  float vars[6][3];
  for (uint32_t civ = 0; civ < 3; civ++) {
    vars[4][civ] = rc_get_var(ch->d3d_combiner_final[1], 24, regs, civ);
    vars[5][civ] = rc_get_var(ch->d3d_combiner_final[1], 16, regs, civ);
  }
  for (uint32_t ci = 0; ci < 3; ci++) {
    regs[0xe][ci] = regs[5][ci] + regs[0xc][ci];
    regs[0xf][ci] = vars[4][ci] * vars[5][ci];
  }
  for (uint32_t civ = 0; civ < 3; civ++) {
    vars[0][civ] = rc_get_var(ch->d3d_combiner_final[0], 24, regs, civ);
    vars[1][civ] = rc_get_var(ch->d3d_combiner_final[0], 16, regs, civ);
    vars[2][civ] = rc_get_var(ch->d3d_combiner_final[0], 8, regs, civ);
    vars[3][civ] = rc_get_var(ch->d3d_combiner_final[0], 0, regs, civ);
  }
  out[3] = rc_get_var(ch->d3d_combiner_final[1], 8, regs, 2);
  for (uint32_t civ = 0; civ < 3; civ++) {
    out[civ] = vars[0][civ] * vars[1][civ] +
      (1.0f - vars[0][civ]) * vars[2][civ] + vars[3][civ];
  }
}

static bool d3d_pixel_shader(NV15State *s, gf_channel *ch,
  float in[16][4], float tmp_regs16[64][4], float tmp_regs32[64][4])
{
  static bool unknown_opcode_reported = false;
  uint32_t ps_offset = ch->d3d_shader_offset;
  uint32_t cc[4];
  for (;;) {
    uint32_t dst_word = nv_dma_read32(s, ch->d3d_shader_obj, ps_offset);
    ps_offset += 4;
    uint32_t src_words[3];
    for (int p = 0; p < 3; p++) {
      src_words[p] = nv_dma_read32(s, ch->d3d_shader_obj, ps_offset);
      ps_offset += 4;
    }
    float cnst[4];
    float params[3][4];
    bool const_loaded = false;
    for (int p = 0; p < 3; p++) {
      uint32_t reg_type = src_words[p] & 3;
      if (reg_type == 2 && !const_loaded) {
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          cnst[comp_index] = uint32_as_float(
            nv_dma_read32(s, ch->d3d_shader_obj, ps_offset));
          ps_offset += 4;
        }
        const_loaded = true;
      }
      uint32_t swizzle[4];
      for (int i = 0; i < 4; i++)
        swizzle[i] = (src_words[p] >> (9 + i * 2)) & 3;
      bool negate = (src_words[p] >> 17) & 1;
      bool src_abs = (p == 0 ? src_words[0] >> 29 : src_words[p] >> 18) & 1;
      for (int comp_index = 0; comp_index < 4; comp_index++) {
        int comp_index_swizzle = swizzle[comp_index];
        if (reg_type == 0) {
          uint32_t tmp_index = (src_words[p] >> 2) & 0x3f;
          bool fp16 = (src_words[p] >> 8) & 1;
          params[p][comp_index] = fp16 ?
            tmp_regs16[tmp_index][comp_index_swizzle] :
            tmp_regs32[tmp_index][comp_index_swizzle];
        } else if (reg_type == 1) {
          uint32_t in_index = (dst_word >> 13) & 0xf;
          params[p][comp_index] = in[in_index][comp_index_swizzle];
        } else if (reg_type == 2) {
          params[p][comp_index] = cnst[comp_index_swizzle];
        } else { // reg_type == 3
          params[p][comp_index] = 0; // default case to avoid non-initialized variable warning
        }
        if (src_abs)
          params[p][comp_index] = fabs(params[p][comp_index]);
        if (negate)
          params[p][comp_index] = -params[p][comp_index];
      }
    }
    uint32_t cond = (src_words[0] >> 18) & 7;
    bool execute;
    if (cond == 7)
      execute = true;
    else {
      execute = false;
      for (int i = 0; i < 4; i++) {
        uint32_t cond_swizzle = (src_words[0] >> (21 + i * 2)) & 3;
        if ((cc[cond_swizzle] & cond) != 0) {
          execute = true;
          break;
        }
      }
    }
    if (execute) {
      uint32_t op = (dst_word >> 24) & 0x3f;
      float op_result[4];
      switch (op) {
        case 0: // NOP
          break;
        case 1: // MOV
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index];
          break;
        case 2: // MUL
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] * params[1][comp_index];
          break;
        case 3: // ADD
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] + params[1][comp_index];
          break;
        case 4: // MAD
          for (int comp_index = 0; comp_index < 4; comp_index++) {
            op_result[comp_index] = params[0][comp_index] * params[1][comp_index] +
              params[2][comp_index];
          }
          break;
        case 5: { // DP3
          float dp3 = dot3(params[0], params[1]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = dp3;
          break;
        }
        case 6: { // DP4
          float dp4 = dot4(params[0], params[1]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = dp4;
          break;
        }
        case 8:   // MIN
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = BX_MIN(params[0][comp_index], params[1][comp_index]);
          break;
        case 9:   // MAX
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = BX_MAX(params[0][comp_index], params[1][comp_index]);
          break;
        case 0xa: // SLT
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] < params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0xb: // SGE
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] >= params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0xc: // SLE
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] <= params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0xd: // SGT
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] > params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0xe: // SNE
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] != params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0xf: // SEQ
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] == params[1][comp_index] ? 1.0f : 0.0f;
          break;
        case 0x10: // FRC
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] - floor(params[0][comp_index]);
          break;
        case 0x11: // FLR
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = floor(params[0][comp_index]);
          break;
        case 0x12: // KIL
          return true;
        case 0x18: { // TXP
          float winv = 1.0f / params[0][3];
          params[0][0] *= winv;
          params[0][1] *= winv;
          params[0][2] *= winv;
        }
        /* fallthrough */
        case 0x2f: // TXL
          // Level of detail parameter is not implemented
        case 0x31: // TXB
          // Bias parameter is not implemented
        case 0x17: { // TEX
          uint32_t tex_unit = (dst_word >> 17) & 0xf;
          gf_texture *tex = &ch->d3d_texture[tex_unit];
          d3d_sample_texture(s, ch, tex, params[0], op_result);
          if (((dst_word >> 21) & 1) != 0)
            for (int comp_index = 0; comp_index < 4; comp_index++)
              op_result[comp_index] = op_result[comp_index] * 2.0f - 1.0f;
          break;
        }
        case 0x1a: { // RCP
          float rcp = 1.0f / params[0][0];
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = rcp;
          break;
        }
        case 0x1c: { // EX2
          float ex2 = exp2(params[0][0]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = ex2;
          break;
        }
        case 0x1d: { // LG2
          float lg2 = log2(params[0][0]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = lg2;
          break;
        }
        case 0x1f: // LRP
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] * params[1][comp_index] +
              (1.0f - params[0][comp_index]) * params[2][comp_index];
          break;
        case 0x22: { // COS
          float cosv = cos(params[0][0]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = cosv;
          break;
        }
        case 0x23: { // SIN
          float sinv = sin(params[0][0]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = sinv;
          break;
        }
        case 0x26: { // POW
          float powv = pow(params[0][0], params[1][0]);
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = powv;
          break;
        }
        case 0x2e: { // DP2A
          float dp2a = 0.0f;
          for (int comp_index = 0; comp_index < 2; comp_index++)
            dp2a += params[0][comp_index] * params[1][comp_index];
          dp2a += params[2][0];
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = dp2a;
          break;
        }
        case 0x34: // TXPBEM
          params[0][0] /= params[0][3];
          params[0][1] /= params[0][3];
          // fallthrough
        case 0x33: { // TEXBEM
          float coords[3];
          coords[0] = params[0][0] + params[1][0] * params[2][0] + params[1][1] * params[2][1];
          coords[1] = params[0][1] + params[1][0] * params[2][2] + params[1][1] * params[2][3];
          coords[2] = 0.0f;
          uint32_t tex_unit = (dst_word >> 17) & 0xf;
          gf_texture *tex = &ch->d3d_texture[tex_unit];
          d3d_sample_texture(s, ch, tex, coords, op_result);
          if (((dst_word >> 21) & 1) != 0)
            for (int comp_index = 0; comp_index < 4; comp_index++)
              op_result[comp_index] = op_result[comp_index] * 2.0f - 1.0f;
          break;
        }
        case 0x36: { // RFL
          reflection(params[0], params[1], op_result);
          op_result[3] = 0.0f; // ignored
          break;
        }
        case 0x38: { // DP2
          float dp2 = 0.0f;
          for (int comp_index = 0; comp_index < 2; comp_index++)
            dp2 += params[0][comp_index] * params[1][comp_index];
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = dp2;
          break;
        }
        case 0x39: // NRM
          normalize_to(params[0], op_result);
          op_result[3] = 0.0f;
          break;
        case 0x3a: // DIV
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = params[0][comp_index] / params[1][0];
          break;
        default:
          for (int comp_index = 0; comp_index < 4; comp_index++)
            op_result[comp_index] = 0.5f;
          if (!unknown_opcode_reported) {
            unknown_opcode_reported = true;
          }
          break;
      }
      bool set_cc = (dst_word >> 8) & 1;
      if (set_cc) {
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          if (op_result[comp_index] < 0.0f)
            cc[comp_index] = 1;
          else if (op_result[comp_index] == 0.0f)
            cc[comp_index] = 2;
          else
            cc[comp_index] = 4;
        }
      }
      bool no_dst = (dst_word >> 30) & 1;
      if (op != 0 && !no_dst) {
        uint32_t mask = (dst_word >> 9) & 0xf;
        uint32_t dst_tmp_reg = (dst_word >> 1) & 0x3f;
        static const float dst_scales[] = {1.0f, 2.0f, 4.0f, 8.0f, 1.0f, 0.5f, 0.25f, 0.125f};
        uint32_t dst_scale = (src_words[1] >> 28) & 7;
        bool dst_fp16 = (dst_word >> 7) & 1;
        bool saturate = (dst_word >> 31) & 1;
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          if ((mask & (1 << comp_index)) != 0) {
            float value = op_result[comp_index] * dst_scales[dst_scale];
            if (saturate) {
              if (value < 0.0f)
                value = 0.0f;
              else if (value > 1.0f)
                value = 1.0f;
            }
            if (dst_fp16)
              tmp_regs16[dst_tmp_reg][comp_index] = value;
            else
              tmp_regs32[dst_tmp_reg][comp_index] = value;
          }
        }
      }
    }
    if ((dst_word & 1) == 1)
      break;
  }
  return false;
}

static void d3d_triangle(NV15State *s, gf_channel *ch, uint32_t base)
{
  if (ch->d3d_shade_mode == 0x00001d00) { // FLAT
    float (*v_pr)[4] = ch->d3d_vertex_data[ch->d3d_vertex_index - 1];
    for (uint32_t vi = 0; vi < 3; vi++) {
      float (*v_in)[4] = ch->d3d_vertex_data[(vi + base) & 3];
      for (uint32_t ci = 0; ci < 4; ci++) {
        v_in[ch->d3d_attrib_in_color[0]][ci] = v_pr[ch->d3d_attrib_in_color[0]][ci];
        v_in[ch->d3d_attrib_in_normal][ci] = v_pr[ch->d3d_attrib_in_normal][ci];
      }
    }
  }
  float vs_out[3][16][4];
  for (uint32_t vi = 0; vi < 3; vi++) {
    float (*v_out)[4] = vs_out[vi];
    float (*v_in)[4] = ch->d3d_vertex_data[(vi + base) & 3];
    if ((ch->d3d_transform_execution_mode & 3) != 0) {
      d3d_vertex_shader(s, ch, v_in, v_out);
    } else {
      float *p = v_out[0];
      for (uint32_t ci = 0; ci < 4; ci++)
        p[ci] = v_in[0][ci];
      float *color_out[2] = {
        v_out[ch->d3d_attrib_out_color[0]],
        v_out[ch->d3d_attrib_out_color[1]]
      };
      float *color_in[2] = {
        v_in[ch->d3d_attrib_in_color[0]],
        v_in[ch->d3d_attrib_in_color[1]]
      };
      if (ch->d3d_lighting_enable) {
        color_out[0][3] = ch->d3d_material_factor[3];
        for (uint32_t ci = 0; ci < 3; ci++) {
          switch (ch->d3d_color_material_ambient) {
            case 0:
            default:
              color_out[0][ci] = ch->d3d_scene_ambient_color[ci];
              break;
            case 1:
              color_out[0][ci] = color_in[0][ci] * ch->d3d_material_factor[ci];
              break;
            case 2:
              color_out[0][ci] = color_in[1][ci] * ch->d3d_material_factor[ci];
              break;
          }
          color_out[1][ci] = 0.0f;
        }
        float nt[3];
        float *n = v_in[ch->d3d_attrib_in_normal];
        normal_to_view(ch, n, nt);
        float pt[3];
        position_to_view3(ch, p, pt);
        for (uint32_t light_index = 0; light_index < 8; light_index++) {
          uint32_t light_type = (ch->d3d_light_enable_mask >> (light_index * 2)) & 3;
          if (light_type == 0)
            continue;
          float n_dot_ld;
          float n_dot_hv;
          float att;
          gf_light *light = &ch->d3d_light[light_index];
          if (light_type == 1) {
            n_dot_ld = dot3(nt, light->inf_direction);
            if (ch->d3d_local_viewer) {
              float ed[3];
              for (uint32_t ci = 0; ci < 3; ci++)
                ed[ci] = ch->d3d_eye_position[ci] - pt[ci];
              normalize(ed);
              float hv[3];
              hv[0] = light->inf_direction[0] + ed[0];
              hv[1] = light->inf_direction[1] + ed[1];
              hv[2] = light->inf_direction[2] + ed[2];
              normalize(hv);
              n_dot_hv = dot3(nt, hv);
            } else {
              n_dot_hv = dot3(nt, light->inf_half_vector);
            }
            att = 1.0f;
          } else {
            float ld[3];
            for (uint32_t ci = 0; ci < 3; ci++)
              ld[ci] = light->local_position[ci] - pt[ci];
            float d = normalize(ld);
            n_dot_ld = dot3(nt, ld);
            float hv[3];
            if (ch->d3d_local_viewer) {
              float ed[3];
              for (uint32_t ci = 0; ci < 3; ci++)
                ed[ci] = ch->d3d_eye_position[ci] - pt[ci];
              normalize(ed);
              hv[0] = ld[0] + ed[0];
              hv[1] = ld[1] + ed[1];
              hv[2] = ld[2] + ed[2];
            } else {
              hv[0] = ld[0];
              hv[1] = ld[1];
              hv[2] = ld[2] + 1.0f;
            }
            normalize(hv);
            n_dot_hv = dot3(nt, hv);
            att = 1.0f / (
              light->local_attenuation[0] +
              light->local_attenuation[1] * d +
              light->local_attenuation[2] * d * d);
            if (light_type == 3) {
              float rho = -dot3(light->spot_direction, ld);
              if (rho > light->spot_direction[3])
                continue;
            }
          }
          if (n_dot_ld < 0.0f)
            n_dot_ld = 0.0f;
          for (uint32_t ci = 0; ci < 3; ci++) {
            float ambient = light->ambient_color[ci];
            float diffuse = att * light->diffuse_color[ci] * n_dot_ld;
            if (ch->d3d_color_material_ambient == 1)
              ambient *= color_in[0][ci];
            else if (ch->d3d_color_material_ambient == 2)
              ambient *= color_in[1][ci];
            if (ch->d3d_color_material_diffuse == 1)
              diffuse *= color_in[0][ci];
            else if (ch->d3d_color_material_diffuse == 2)
              diffuse *= color_in[1][ci];
            color_out[0][ci] += ambient + diffuse;
          }
          if (n_dot_hv < 0.0f)
            n_dot_hv = 0.0f;
          if (n_dot_hv != 0.0f) {
            float pf = pow(n_dot_hv, ch->d3d_specular_power);
            for (uint32_t ci = 0; ci < 3; ci++) {
              color_out[ch->d3d_separate_specular][ci] +=
                att * light->specular_color[ci] * pf;
            }
          }
        }
      } else {
        for (uint32_t ci = 0; ci < 4; ci++) {
          color_out[0][ci] = color_in[0][ci];
          color_out[1][ci] = 0.0f;
        }
      }
      for (uint32_t i = 0; i < ch->d3d_tex_coord_count; i++) {
        float *tc = v_out[ch->d3d_attrib_out_tex_coord[i]];
        for (int comp_index = 0; comp_index < 4; comp_index++) {
          uint32_t texgen = ch->d3d_texgen[i][comp_index];
          switch (texgen) {
            case 0x0000:   // disabled
              tc[comp_index] = v_in[
                ch->d3d_attrib_in_tex_coord[i]][comp_index];
              break;
            case 0x2400: { // EYE_LINEAR
              float pt[4];
              position_to_view4(ch, p, pt);
              tc[comp_index] = dot4(ch->d3d_texgen_plane[i][comp_index], pt);
              break;
            }
            case 0x2401:   // OBJECT_LINEAR
              tc[comp_index] = dot4(ch->d3d_texgen_plane[i][comp_index], p);
              break;
            case 0x2402:   // SPHERE_MAP
            case 0x8512: { // REFLECTION_MAP
              float nt[3];
              float *n = v_in[ch->d3d_attrib_in_normal];
              normal_to_view(ch, n, nt);
              float pt[3];
              position_to_view3(ch, p, pt);
              float u[3];
              normalize_to(pt, u);
              float r[3];
              float ntu = dot3(nt, u);
              r[0] = u[0] - 2 * nt[0] * ntu;
              r[1] = u[1] - 2 * nt[1] * ntu;
              r[2] = u[2] - 2 * nt[2] * ntu;
              if (texgen == 0x2402) { // SPHERE_MAP
                float m = 2 * sqrt(r[0] * r[0] + r[1] * r[1] + (r[2] + 1.0f) * (r[2] + 1.0f));
                if (comp_index < 2)
                  tc[comp_index] = r[comp_index] / m + 0.5f;
                else
                  tc[comp_index] = 0.0f;
              } else {
                if (comp_index < 3)
                  tc[comp_index] = r[comp_index];
                else
                  tc[comp_index] = 0.0f;
              }
              break;
            }
            case 0x8511: { // NORMAL_MAP
              if (comp_index < 3) {
                float *n = v_in[ch->d3d_attrib_in_normal];
                float *r = &ch->d3d_inverse_model_view_matrix[comp_index * 4];
                tc[comp_index] = dot3(n, r);
              } else
                tc[comp_index] = 0.0f;
              break;
            }
            default:       // not implemented
              tc[comp_index] = 0.5f;
              break;
          }
        }
        if (ch->d3d_texture_matrix_enable[i]) {
          float ttc[4];
          float *m = ch->d3d_texture_matrix[i];
          ttc[0] = tc[0] * m[0]  + tc[1] * m[1]  + tc[2] * m[2]  + tc[3] * m[3];
          ttc[1] = tc[0] * m[4]  + tc[1] * m[5]  + tc[2] * m[6]  + tc[3] * m[7];
          ttc[2] = tc[0] * m[8]  + tc[1] * m[9]  + tc[2] * m[10] + tc[3] * m[11];
          ttc[3] = tc[0] * m[12] + tc[1] * m[13] + tc[2] * m[14] + tc[3] * m[15];
          for (int comp_index = 0; comp_index < 4; comp_index++)
            tc[comp_index] = ttc[comp_index];
        }
      }
      if (ch->d3d_fog_enable) {
        float fog_dist;
        switch (ch->d3d_fog_gen_mode) {
          case 0:   // SPEC_ALPHA
            fog_dist = v_in[ch->d3d_attrib_in_color[1]][3];
            break;
          case 1: { // RADIAL
            float pt[3];
            position_to_view3(ch, p, pt);
            fog_dist = length(pt);
            break;
          }
          case 2:   // PLANAR
          case 3: { // ABS_PLANAR
            float *m = ch->d3d_model_view_matrix[0];
            fog_dist = p[0] * m[8] + p[1] * m[9] + p[2] * m[10] + p[3] * m[11];
            if (ch->d3d_fog_gen_mode == 3) // ABS_PLANAR
              fog_dist = fabs(fog_dist);
            break;
          }
          default:  // not implemented
            fog_dist = 3.0f;
            break;
        }
        v_out[ch->d3d_attrib_out_fogc][0] = fog_dist;
      }
      if (ch->d3d_view_matrix_enable == 0 ||
          ch->d3d_view_matrix_enable == 2 ||
          ch->d3d_view_matrix_enable == 6) {
        float tp[4];
        float *m = ch->d3d_composite_matrix;
        tp[0] = p[0] * m[0]  + p[1] * m[1]  + p[2] * m[2]  + p[3] * m[3];
        tp[1] = p[0] * m[4]  + p[1] * m[5]  + p[2] * m[6]  + p[3] * m[7];
        tp[2] = p[0] * m[8]  + p[1] * m[9]  + p[2] * m[10] + p[3] * m[11];
        tp[3] = p[0] * m[12] + p[1] * m[13] + p[2] * m[14] + p[3] * m[15];
        for (int comp_index = 0; comp_index < 4; comp_index++)
          p[comp_index] = tp[comp_index];
      }
    }
    for (uint32_t i = 0; i < 2; i++) {
      if (ch->d3d_attrib_out_enable[i]) {
        float *color = v_out[ch->d3d_attrib_out_color[i]];
        for (uint32_t ci = 0; ci < 4; ci++)
          color[ci] = BX_MIN(BX_MAX(color[ci], 0.0f), 1.0f);
      }
    }
  }
  bool clipped[3];
  uint32_t clip_count = 0;
  float clip_thresh = s->card_type <= 0x20 ?
    ch->d3d_viewport_offset[2] - ch->d3d_clip_min : 1.0f;
  for (int v = 0; v < 3; v++) {
    clipped[v] = vs_out[v][0][2] < -vs_out[v][0][3] * clip_thresh;
    if (clipped[v])
      clip_count++;
  }
  if (clip_count == 0)
    d3d_triangle_clipped(s, ch, vs_out[0], vs_out[1], vs_out[2]);
  else if (clip_count == 3)
    return;
  else {
    uint32_t intersection_index = 0;
    float intersections[2][16][4];
    for (int v0 = 0; v0 < 3; v0++) {
      uint32_t v1 = (v0 + 1) % 3;
      if (clipped[v0] != clipped[v1]) {
        float k = vs_out[v1][0][2] + vs_out[v1][0][3] * clip_thresh;
        float t = k / (k - vs_out[v0][0][2] - vs_out[v0][0][3] * clip_thresh);
        float omt = 1.0f - t;
        for (int a = 0; a < 16; a++) {
          for (int comp_index = 0; comp_index < 4; comp_index++) {
            intersections[intersection_index][a][comp_index] =
              t * vs_out[v0][a][comp_index] + omt * vs_out[v1][a][comp_index];
          }
        }
        intersection_index++;
      }
    }
    if (clip_count == 2) {
      if (!clipped[0])
        d3d_triangle_clipped(s, ch, vs_out[0], intersections[0], intersections[1]);
      else if (!clipped[1])
        d3d_triangle_clipped(s, ch, intersections[0], vs_out[1], intersections[1]);
      else
        d3d_triangle_clipped(s, ch, intersections[1], intersections[0], vs_out[2]);
    } else {
      if (clipped[0]) {
        d3d_triangle_clipped(s, ch, intersections[0], vs_out[1], vs_out[2]);
        d3d_triangle_clipped(s, ch, intersections[1], intersections[0], vs_out[2]);
      } else if (clipped[1]) {
        d3d_triangle_clipped(s, ch, vs_out[0], intersections[0], vs_out[2]);
        d3d_triangle_clipped(s, ch, intersections[0], intersections[1], vs_out[2]);
      } else {
        d3d_triangle_clipped(s, ch, vs_out[0], vs_out[1], intersections[0]);
        d3d_triangle_clipped(s, ch, vs_out[0], intersections[0], intersections[1]);
      }
    }
  }
}

static void d3d_clip_to_screen(NV15State *s, gf_channel *ch, float pos_clip[4], float pos_screen[4])
{
  pos_screen[3] = 1.0f / pos_clip[3];
  if (((ch->d3d_transform_execution_mode & 3) != 0 &&
      (ch->d3d_transform_execution_mode & 0x100) == 0 &&
      s->card_type >= 0x35) ||
      (ch->d3d_transform_execution_mode & 3) == 0) {
    for (int i = 0; i < 3; i++) {
      pos_screen[i] = pos_clip[i] * pos_screen[3];
      if ((ch->d3d_view_matrix_enable & 1) != 0) {
        pos_screen[i] *= ch->d3d_model_view_matrix[1][i];
        pos_screen[i] += ch->d3d_model_view_matrix[1][i + 4];
      } else {
        if (s->card_type > 0x20)
          pos_screen[i] *= ch->d3d_viewport_scale[i];
        pos_screen[i] += ch->d3d_viewport_offset[i];
      }
    }
    pos_screen[0] += ch->d3d_window_offset_x;
    pos_screen[1] += ch->d3d_window_offset_y;
  } else {
    for (int i = 0; i < 3; i++)
      pos_screen[i] = pos_clip[i];
  }
}

static void d3d_triangle_clipped(NV15State *s, gf_channel *ch, float v0[16][4], float v1[16][4], float v2[16][4])
{
  float sp0[4], sp1[4], sp2[4];
  d3d_clip_to_screen(s, ch, v0[0], sp0);
  d3d_clip_to_screen(s, ch, v1[0], sp1);
  d3d_clip_to_screen(s, ch, v2[0], sp2);
  double b012 = edge_function(sp0, sp1, sp2);
  bool front_face_cw = ch->d3d_front_face == 0x00000900;
  bool clockwise = b012 > 0.0;
  bool front_face = (clockwise != ch->d3d_triangle_flip) == front_face_cw;
  if (ch->d3d_cull_face_enable) {
    if ((ch->d3d_cull_face == 0x00000405 && !front_face) ||
        (ch->d3d_cull_face == 0x00000404 && front_face) ||
        (ch->d3d_cull_face == 0x00000408))
      return;
  }
  uint32_t surf_x1 = ch->d3d_clip_horizontal & 0xFFFF;
  uint32_t surf_y1 = ch->d3d_clip_vertical & 0xFFFF;
  uint32_t surf_x2 = surf_x1 + (ch->d3d_clip_horizontal >> 16);
  uint32_t surf_y2 = surf_y1 + (ch->d3d_clip_vertical >> 16);
  int32_t tri_x1 = BX_MIN(BX_MIN(sp0[0], sp1[0]), sp2[0]);
  int32_t tri_y1 = BX_MIN(BX_MIN(sp0[1], sp1[1]), sp2[1]);
  int32_t tri_x2 = BX_MAX(BX_MAX(sp0[0], sp1[0]), sp2[0]);
  int32_t tri_y2 = BX_MAX(BX_MAX(sp0[1], sp1[1]), sp2[1]);
  uint32_t draw_x1 = BX_MIN(BX_MAX(tri_x1, (int32_t)surf_x1), (int32_t)surf_x2);
  uint32_t draw_y1 = BX_MIN(BX_MAX(tri_y1, (int32_t)surf_y1), (int32_t)surf_y2);
  uint32_t draw_x2 = BX_MIN(BX_MAX(tri_x2 + 1, (int32_t)surf_x1), (int32_t)surf_x2);
  uint32_t draw_y2 = BX_MIN(BX_MAX(tri_y2 + 1, (int32_t)surf_y1), (int32_t)surf_y2);
  if (draw_x2 < draw_x1 || draw_y2 < draw_y1)
    return; // overflow
  uint32_t draw_width = draw_x2 - draw_x1;
  uint32_t draw_height = draw_y2 - draw_y1;
  if (!d3d_window_clip(s, ch, &draw_x1, &draw_y1, &draw_width, &draw_height))
    return;
  if (!d3d_viewport_clip(s, ch, &draw_x1, &draw_y1, &draw_width, &draw_height))
    return;
  if (!d3d_scissor_clip(s, ch, &draw_x1, &draw_y1, &draw_width, &draw_height))
    return;
  uint32_t pitch = ch->d3d_surface_pitch_a & 0xFFFF;
  uint32_t pitch_zeta = d3d_get_surface_pitch_z(s, ch);
  uint32_t draw_offset = ch->d3d_surface_color_offset +
    draw_y1 * pitch + draw_x1 * ch->d3d_color_bytes;
  uint32_t draw_offset_zeta = ch->d3d_surface_zeta_offset +
    draw_y1 * pitch_zeta + draw_x1 * ch->d3d_depth_bytes;
  uint32_t redraw_offset = nv_dma_lin_lookup(s, ch->d3d_color_obj, draw_offset) -
    s->disp_offset;
  bool interpolate[16];
  for (int a = 0; a < 16; a++) {
    bool result = false;
    for (int comp_index = 0; comp_index < 4; comp_index++) {
      result |= v0[a][comp_index] != v1[a][comp_index];
      result |= v1[a][comp_index] != v2[a][comp_index];
    }
    interpolate[a] = result;
  }
  float ps_in[16][4];
  float rc_regs[16][4];
  float fog_factor = 1.0f;
  ps_in[3][1] = fog_factor;
  rc_regs[3][3] = fog_factor;
  for (uint32_t ci = 0; ci < 3; ci++)
    rc_regs[3][ci] = ch->d3d_fog_color[ci];
  for (uint32_t i = 0; i < 2; i++)
    if (!interpolate[ch->d3d_attrib_out_color[i]])
      for (int comp_index = 0; comp_index < 4; comp_index++)
        ps_in[i + 1][comp_index] = v0[ch->d3d_attrib_out_color[i]][comp_index];
  for (uint32_t i = 0; i < ch->d3d_tex_coord_count; i++)
    if (!interpolate[ch->d3d_attrib_out_tex_coord[i]])
      for (int comp_index = 0; comp_index < 4; comp_index++)
        ps_in[i + 4][comp_index] = v0[ch->d3d_attrib_out_tex_coord[i]][comp_index];
  float xy[2];
  xy[1] = draw_y1 + 0.5f;
  double b012inv = 1.0 / b012;
  bool stencil_test_enable = ch->d3d_stencil_test_enable && ch->d3d_depth_bytes != 2;
  bool zstencil_enable = ch->d3d_depth_test_enable || stencil_test_enable;
  bool ps_enable = ch->d3d_shader_obj != 0;
  bool rc_enable = ch->d3d_combiner_control_num_stages != 0;
  float ps_tmp_regs16[64][4];
  float ps_tmp_regs32[64][4];
  float (*ps_tmp_regs_exp)[4] = ps_tmp_regs16;
  if (ps_enable && ((ch->d3d_shader_control & 0x00000040) != 0))
    ps_tmp_regs_exp = ps_tmp_regs32;
  for (uint16_t y = 0; y < draw_height; y++, xy[1]++) {
    xy[0] = draw_x1 + 0.5f;
    for (uint16_t x = 0; x < draw_width; x++, xy[0]++) {
      double b0 = edge_function(sp1, sp2, xy);
      if (clockwise) {
        if (b0 < 0.0)
          continue;
      } else {
        if (b0 > 0.0)
          continue;
      }
      double b1 = edge_function(sp2, sp0, xy);
      if (clockwise) {
        if (b1 < 0.0)
          continue;
      } else {
        if (b1 > 0.0)
          continue;
      }
      double b2 = edge_function(sp0, sp1, xy);
      if (clockwise) {
        if (b2 < 0.0)
          continue;
      } else {
        if (b2 > 0.0)
          continue;
      }
      b0 *= b012inv;
      b1 *= b012inv;
      b2 *= b012inv;
      float z = sp0[2] * b0 + sp1[2] * b1 + sp2[2] * b2;
      if (z > ch->d3d_clip_max)
        continue;
      uint32_t z_new = 0;
      uint8_t stencil = 0x00;
      if (zstencil_enable) {
        uint32_t z_prev;
        if (ch->d3d_depth_bytes == 2)
          z_prev = nv_dma_read16(s, ch->d3d_zeta_obj, draw_offset_zeta + x * 2);
        else {
          uint32_t zstencil = nv_dma_read32(s, ch->d3d_zeta_obj, draw_offset_zeta + x * 4);
          z_prev = zstencil >> 8;
          stencil = (uint8_t)zstencil;
        }
        bool depth_test_pass;
        if (ch->d3d_depth_test_enable) {
          if (s->card_type <= 0x20)
            z_new = z;
          else if (ch->d3d_depth_bytes == 2)
            z_new = z * 65535.0f;
          else
            z_new = z * 16777215.0f;
          depth_test_pass = compare(ch->d3d_depth_func, z_new, z_prev);
        } else
          depth_test_pass = true;
        if (stencil_test_enable) {
          bool stencil_test_pass = compare(ch->d3d_stencil_func,
            ch->d3d_stencil_func_ref & ch->d3d_stencil_func_mask,
            stencil & ch->d3d_stencil_func_mask);
          uint32_t stencil_op;
          if (stencil_test_pass) {
            if (depth_test_pass)
              stencil_op = ch->d3d_stencil_op_dppass;
            else
              stencil_op = ch->d3d_stencil_op_dpfail;
          } else {
            stencil_op = ch->d3d_stencil_op_sfail;
          }
          switch (stencil_op) {
            case 0x1e00: // KEEP
            default:
              break;
            case 0x0000: // ZERO
              stencil = 0x00;
              break;
            case 0x1e01: // REPLACE
              stencil = ch->d3d_stencil_func_ref;
              break;
            case 0x1e02: // INCRSAT
              if (stencil < 0xff)
                stencil++;
              break;
            case 0x1e03: // DECRSAT
              if (stencil > 0x00)
                stencil--;
              break;
            case 0x150a: // INVERT
              stencil = ~stencil;
              break;
            case 0x8507: // INCR
              stencil++;
              break;
            case 0x8508: // DECR
              stencil--;
              break;
          }
          if (stencil_op != 0x1e00) {
            stencil &= ch->d3d_stencil_mask;
            nv_dma_write8(s, ch->d3d_zeta_obj, draw_offset_zeta + x * 4, stencil);
          }
          if (!stencil_test_pass)
            continue;
        }
        if (!depth_test_pass)
          continue;
      }
      ps_in[0][3] = sp0[3] * b0 + sp1[3] * b1 + sp2[3] * b2;
      b0 *= sp0[3] / ps_in[0][3];
      b1 *= sp1[3] / ps_in[0][3];
      b2 *= sp2[3] / ps_in[0][3];
      for (int i = 0; i < 2; i++) {
        if (interpolate[ch->d3d_attrib_out_color[i]]) {
          for (int comp_index = 0; comp_index < 4; comp_index++) {
            ps_in[i + 1][comp_index] =
              v0[ch->d3d_attrib_out_color[i]][comp_index] * b0 +
              v1[ch->d3d_attrib_out_color[i]][comp_index] * b1 +
              v2[ch->d3d_attrib_out_color[i]][comp_index] * b2;
          }
        }
      }
      for (uint32_t i = 0; i < ch->d3d_tex_coord_count; i++) {
        if (interpolate[ch->d3d_attrib_out_tex_coord[i]]) {
          for (int comp_index = 0; comp_index < 4; comp_index++) {
            ps_in[i + 4][comp_index] =
              v0[ch->d3d_attrib_out_tex_coord[i]][comp_index] * b0 +
              v1[ch->d3d_attrib_out_tex_coord[i]][comp_index] * b1 +
              v2[ch->d3d_attrib_out_tex_coord[i]][comp_index] * b2;
          }
        }
      }
      for (int comp_index = 0; comp_index < 4; comp_index++)
        ps_tmp_regs16[0][comp_index] = ps_in[1][comp_index];
      if (ch->d3d_fog_enable) {
        float fog_dist =
          v0[ch->d3d_attrib_out_fogc][0] * b0 +
          v1[ch->d3d_attrib_out_fogc][0] * b1 +
          v2[ch->d3d_attrib_out_fogc][0] * b2;
        switch (ch->d3d_fog_mode) {
          case 0x2601: // LINEAR
            fog_factor = ch->d3d_fog_params[1] *
              fog_dist + ch->d3d_fog_params[0] - 1.0f;
            break;
          case 0x804:  // LINEAR_ABS
            fog_factor = ch->d3d_fog_params[1] *
              fabs(fog_dist) + ch->d3d_fog_params[0] - 1.0f;
            break;
          case 0x800:  // EXP
            fog_factor = exp2(16.0f * (ch->d3d_fog_params[1] *
              fog_dist + ch->d3d_fog_params[0] - 1.5f));
            break;
          case 0x802:  // EXP_ABS
            fog_factor = exp2(16.0f * (ch->d3d_fog_params[1] *
              fabs(fog_dist) + ch->d3d_fog_params[0] - 1.5f));
            break;
          case 0x801:  // EXP2
            fog_factor = exp(-pow(4.709f * (ch->d3d_fog_params[1] *
              fog_dist + ch->d3d_fog_params[0] - 1.5f), 2.0f));
            break;
          case 0x803:  // EXP2_ABS
            fog_factor = exp(-pow(4.709f * (ch->d3d_fog_params[1] *
              fabs(fog_dist) + ch->d3d_fog_params[0] - 1.5f), 2.0f));
            break;
          default:     // not implemented
            fog_factor = 0.5f;
            break;
        }
        if (fog_factor < 0.0f)
          fog_factor = 0.0f;
        if (fog_factor > 1.0f)
          fog_factor = 1.0f;
        if (ps_enable)
          ps_in[3][1] = fog_factor;
        if (rc_enable)
          rc_regs[3][3] = fog_factor;
      }
      if (ps_enable) {
        ps_in[0][0] = xy[0] - ch->d3d_window_offset_x;
        ps_in[0][1] = ch->d3d_viewport_height - (xy[1] - ch->d3d_window_offset_y);
        ps_in[0][2] = 0.0f;
        // eye-ray vector for texm3x3vspec
        ps_in[15][0] = ps_in[5][3];
        ps_in[15][1] = ps_in[6][3];
        ps_in[15][2] = ps_in[7][3];
        if (d3d_pixel_shader(s, ch, ps_in, rc_enable ? &rc_regs[8] : ps_tmp_regs16, ps_tmp_regs32))
          continue;
      }
      if (rc_enable) {
        for (uint32_t ci = 0; ci < 4; ci++) {
          rc_regs[0][ci] = 0.0f;
          rc_regs[4][ci] = ps_in[1][ci];
          rc_regs[5][ci] = ps_in[2][ci];
        }
        rc_regs[0xe][3] = 0.0f;
        rc_regs[0xf][3] = 0.0f;
        if (!ps_enable) {
          float uv[2] = { 0.0f, 0.0f };
          for (uint32_t t = 0; t < ch->d3d_tex_coord_count; t++) {
            switch (ch->d3d_tex_shader_op[t]) {
              case 0x00:   // NONE
                break;
              case 0x01:   // PROJECT2D
              case 0x03: { // CUBEMAP
                gf_texture *tex = &ch->d3d_texture[t];
                d3d_sample_texture(s, ch, tex, ps_in[4 + t], rc_regs[8 + t]);
                break;
              }
              case 0x06: { // BUMPENVMAP
                float *in_coords = ps_in[4 + t];
                float *prev_color = rc_regs[8 + ch->d3d_tex_shader_previous[t]];
                float coords[3];
                gf_texture *tex = &ch->d3d_texture[t];
                coords[0] = in_coords[0] / in_coords[3] +
                  tex->offset_matrix[0] * prev_color[2] +
                  tex->offset_matrix[3] * prev_color[1];
                coords[1] = in_coords[1] / in_coords[3] +
                  tex->offset_matrix[1] * prev_color[2] +
                  tex->offset_matrix[2] * prev_color[1];
                coords[2] = 0.0f;
                d3d_sample_texture(s, ch, tex, coords, rc_regs[8 + t]);
                break;
              }
              case 0x0c: { // DOT_RFLCT_SPEC
                float *input_tex = rc_regs[8 + ch->d3d_tex_shader_previous[t]];
                float w = dot3m(ps_in[4 + t], input_tex, ch->d3d_tex_shader_dotmapping[t]);
                float n[3] = { uv[0], uv[1], w };
                float e[3] = { ps_in[4 + 1][3], ps_in[4 + 2][3], ps_in[4 + 3][3] };
                float rv[3];
                reflection(n, e, rv);
                gf_texture *tex = &ch->d3d_texture[t];
                d3d_sample_texture(s, ch, tex, rv, rc_regs[8 + t]);
                break;
              }
              case 0x11: { // DOTPRODUCT
                float *input_tex = rc_regs[8 + ch->d3d_tex_shader_previous[t]];
                uv[t == 1 ? 0 : 1] = dot3m(ps_in[4 + t], input_tex, ch->d3d_tex_shader_dotmapping[t]);
                break;
              }
              default: {   // not implemented
                float *color = rc_regs[8 + t];
                color[0] = 0.0f;
                color[1] = 0.5f;
                color[2] = 0.5f;
                color[3] = 1.0f;
                break;
              }
            }
          }
        }
        d3d_register_combiners(s, ch, rc_regs, ps_tmp_regs_exp[0]);
      }
      float a = BX_MIN(BX_MAX(ps_tmp_regs_exp[0][3], 0.0f), 1.0f);
      if (ch->d3d_alpha_test_enable) {
        if (!compare(ch->d3d_alpha_func, (uint32_t)(a * 255.0f), ch->d3d_alpha_ref))
          continue;
      }
      float r = BX_MIN(BX_MAX(ps_tmp_regs_exp[0][0], 0.0f), 1.0f);
      float g = BX_MIN(BX_MAX(ps_tmp_regs_exp[0][1], 0.0f), 1.0f);
      float b = BX_MIN(BX_MAX(ps_tmp_regs_exp[0][2], 0.0f), 1.0f);
      if (ch->d3d_blend_enable) {
        float sr = r;
        float sg = g;
        float sb = b;
        float sa = a;
        float dr, dg, db, da;
        if (ch->d3d_color_bytes == 2) {
          uint16_t color = nv_dma_read16(s, ch->d3d_color_obj, draw_offset + x * 2);
          dr = ((color >> 11) & 0x1f) / 31.0f;
          dg = ((color >> 5) & 0x3f) / 63.0f;
          db = ((color >> 0) & 0x1f) / 31.0f;
          da = 1.0f;
        } else if (ch->d3d_color_bytes == 4) {
          uint32_t color = nv_dma_read32(s, ch->d3d_color_obj, draw_offset + x * 4);
          dr = ((color >> 16) & 0xff) / 255.0f;
          dg = ((color >> 8) & 0xff) / 255.0f;
          db = ((color >> 0) & 0xff) / 255.0f;
          da = ((color >> 24) & 0xff) / 255.0f;
        } else {
          uint8_t color = nv_dma_read8(s, ch->d3d_color_obj, draw_offset + x);
          dr = 0.0f;
          dg = 0.0f;
          db = color / 255.0f;
          da = 1.0f;
        }
        r = blend_equation(ch->d3d_blend_equation_rgb,
              sr, blend_factor(ch->d3d_blend_sfactor_rgb, sr, sa, dr, da,
                               ch->d3d_blend_color[0], ch->d3d_blend_color[3]),
              dr, blend_factor(ch->d3d_blend_dfactor_rgb, sr, sa, dr, da,
                               ch->d3d_blend_color[0], ch->d3d_blend_color[3]));
        g = blend_equation(ch->d3d_blend_equation_rgb,
              sg, blend_factor(ch->d3d_blend_sfactor_rgb, sg, sa, dg, da,
                               ch->d3d_blend_color[1], ch->d3d_blend_color[3]),
              dg, blend_factor(ch->d3d_blend_dfactor_rgb, sg, sa, dg, da,
                               ch->d3d_blend_color[1], ch->d3d_blend_color[3]));
        b = blend_equation(ch->d3d_blend_equation_rgb,
              sb, blend_factor(ch->d3d_blend_sfactor_rgb, sb, sa, db, da,
                               ch->d3d_blend_color[2], ch->d3d_blend_color[3]),
              db, blend_factor(ch->d3d_blend_dfactor_rgb, sb, sa, db, da,
                               ch->d3d_blend_color[2], ch->d3d_blend_color[3]));
        a = blend_equation(ch->d3d_blend_equation_alpha,
              sa, blend_factor(ch->d3d_blend_sfactor_alpha, sa, sa, da, da,
                               ch->d3d_blend_color[3], ch->d3d_blend_color[3]),
              da, blend_factor(ch->d3d_blend_dfactor_alpha, sa, sa, da, da,
                               ch->d3d_blend_color[3], ch->d3d_blend_color[3]));
        r = BX_MIN(BX_MAX(r, 0.0f), 1.0f);
        g = BX_MIN(BX_MAX(g, 0.0f), 1.0f);
        b = BX_MIN(BX_MAX(b, 0.0f), 1.0f);
        a = BX_MIN(BX_MAX(a, 0.0f), 1.0f);
      }
      if (ch->d3d_color_mask != 0) {
        if (ch->d3d_color_bytes == 2) {
          uint8_t r5 = r * 31.0f + 0.5f;
          uint8_t g6 = g * 63.0f + 0.5f;
          uint8_t b5 = b * 31.0f + 0.5f;
          uint16_t color = b5 << 0 | g6 << 5 | r5 << 11;
          if (ch->d3d_color_mask == 0x01010101) {
            nv_dma_write16(s, ch->d3d_color_obj, draw_offset + x * 2, color);
          } else {
            uint16_t dstcolor = nv_dma_read16(s, ch->d3d_color_obj, draw_offset + x * 2);
            dstcolor &= ~ch->d3d_color_mask_565;
            dstcolor |= color & ch->d3d_color_mask_565;
            nv_dma_write16(s, ch->d3d_color_obj, draw_offset + x * 2, dstcolor);
          }
        } else if (ch->d3d_color_bytes == 4) {
          uint8_t r8 = r * 255.0f + 0.5f;
          uint8_t g8 = g * 255.0f + 0.5f;
          uint8_t b8 = b * 255.0f + 0.5f;
          uint8_t a8 = a * 255.0f + 0.5f;
          uint32_t color = b8 << 0 | g8 << 8 | r8 << 16 | a8 << 24;
          if (ch->d3d_color_mask == 0x01010101) {
            nv_dma_write32(s, ch->d3d_color_obj, draw_offset + x * 4, color);
          } else {
            uint32_t dstcolor = nv_dma_read32(s, ch->d3d_color_obj, draw_offset + x * 4);
            dstcolor &= ~ch->d3d_color_mask_8888;
            dstcolor |= color & ch->d3d_color_mask_8888;
            nv_dma_write32(s, ch->d3d_color_obj, draw_offset + x * 4, dstcolor);
          }
        } else {
          uint8_t color = b * 255.0f + 0.5f;
          nv_dma_write8(s, ch->d3d_color_obj, draw_offset + x, color);
        }
      }
      if (ch->d3d_depth_test_enable && ch->d3d_depth_write_enable) {
        if (ch->d3d_depth_bytes == 2)
          nv_dma_write16(s, ch->d3d_zeta_obj, draw_offset_zeta + x * 2, z_new);
        else
          nv_dma_write32(s, ch->d3d_zeta_obj, draw_offset_zeta + x * 4, (z_new << 8) | stencil);
      }
    }
    draw_offset += pitch;
    draw_offset_zeta += pitch_zeta;
  }
  nv_redraw_area_nd_off(s, redraw_offset, draw_width, draw_height);
}

static void d3d_process_vertex(NV15State *s, gf_channel *ch, bool immediate)
{
  if (immediate) {
    for (uint32_t ai = 0; ai < ch->d3d_attrib_count; ai++) {
      for (uint32_t ci = 0; ci < 4; ci++) {
        ch->d3d_vertex_data[ch->d3d_vertex_index][ai][ci] =
          ch->d3d_vertex_data_imm[ai][ci];
      }
    }
  }
  if (ch->d3d_vertex_data_array_format_homogeneous[0]) {
    float *p = ch->d3d_vertex_data[ch->d3d_vertex_index][0];
    p[3] = 1.0f / p[3];
    p[0] *= p[3];
    p[1] *= p[3];
    p[2] *= p[3];
  }
  ch->d3d_vertex_index++;
  switch (ch->d3d_begin_end) {
    case 5:      // TRIANGLES
    case 0x1012: // TRIANGLELIST
    case 0x101a:
      if (ch->d3d_vertex_index == 3) {
        d3d_triangle(s, ch, 0);
        ch->d3d_vertex_index = 0;
      }
      break;
    case 6:      // TRIANGLE_STRIP
      if (ch->d3d_vertex_index == 3 || ch->d3d_primitive_done) {
        d3d_triangle(s, ch, 0);
        ch->d3d_primitive_done = true;
        ch->d3d_triangle_flip = !ch->d3d_triangle_flip;
        if (ch->d3d_vertex_index == 3)
          ch->d3d_vertex_index = 0;
      }
      break;
    case 7:      // TRIANGLE_FAN
    case 0xa:    // POLYGON
    case 0x1015:
    case 0x1017:
      if (ch->d3d_vertex_index == 3 || ch->d3d_primitive_done) {
        d3d_triangle(s, ch, 0);
        ch->d3d_primitive_done = true;
        ch->d3d_triangle_flip = !ch->d3d_triangle_flip;
        if (ch->d3d_vertex_index == 3)
          ch->d3d_vertex_index = 1;
      }
      break;
    case 8:      // QUADS
      if (ch->d3d_vertex_index == 4) {
        d3d_triangle(s, ch, 0);
        d3d_triangle(s, ch, 2);
        ch->d3d_vertex_index = 0;
      }
      break;
    case 9:      // QUAD_STRIP
      if (ch->d3d_vertex_index == 4 ||
          (ch->d3d_vertex_index == 2 && ch->d3d_primitive_done)) {
        if (ch->d3d_vertex_index == 4) {
          d3d_triangle(s, ch, 0);
          ch->d3d_triangle_flip = true;
          d3d_triangle(s, ch, 1);
          ch->d3d_triangle_flip = false;
          ch->d3d_primitive_done = true;
          ch->d3d_vertex_index = 0;
        } else {
          d3d_triangle(s, ch, 2);
          ch->d3d_triangle_flip = true;
          d3d_triangle(s, ch, 3);
          ch->d3d_triangle_flip = false;
        }
      }
      break;
    default:     // not implemented
      ch->d3d_vertex_index = 0;
      break;
  }
}

static void d3d_load_vertex(NV15State *s, gf_channel *ch, uint32_t index)
{
  uint32_t index_adj = ch->d3d_vertex_data_base_index + index;
  for (uint32_t ai = 0; ai < ch->d3d_attrib_count; ai++) {
    uint32_t comp_count = ch->d3d_vertex_data_array_format_size[ai];
    if (comp_count != 0) {
      uint32_t array_offset = ch->d3d_vertex_data_array_offset[ai];
      uint32_t array_obj = array_offset & 0x80000000 ?
        ch->d3d_vertex_b_obj : ch->d3d_vertex_a_obj;
      array_offset &= 0x7fffffff;
      array_offset -= nv_ramin_read32(s, array_obj) >> 20; // why?
      uint32_t attrib_stride = ch->d3d_vertex_data_array_format_stride[ai];
      array_offset += index_adj * attrib_stride;
      ch->d3d_vertex_data[ch->d3d_vertex_index][ai][2] = 0.0f;
      ch->d3d_vertex_data[ch->d3d_vertex_index][ai][3] = 1.0f;
      uint32_t format_type = ch->d3d_vertex_data_array_format_type[ai];
      if ((format_type == 0 || format_type == 4) && comp_count == 4) {
        uint32_t value = nv_dma_read32(s, array_obj, array_offset);
        unpack_attribute(value, format_type == 0,
          ch->d3d_vertex_data[ch->d3d_vertex_index][ai]);
      } else if (format_type == 5 && comp_count == 2) {
        uint32_t value = nv_dma_read32(s, array_obj, array_offset);
        ch->d3d_vertex_data[ch->d3d_vertex_index][ai][0] = (float)(int16_t)value;
        ch->d3d_vertex_data[ch->d3d_vertex_index][ai][1] = (float)(int16_t)(value >> 16);
      } else {
        for (uint32_t ci = 0; ci < comp_count; ci++) {
          uint32_t ui32 = nv_dma_read32(s, array_obj, array_offset + ci * 4);
          ch->d3d_vertex_data[ch->d3d_vertex_index][ai][ci] = uint32_as_float(ui32);
        }
      }
    } else {
      for (uint32_t ci = 0; ci < 4; ci++) {
        ch->d3d_vertex_data[ch->d3d_vertex_index][ai][ci] =
          ch->d3d_vertex_data_imm[ai][ci];
      }
    }
  }
  d3d_process_vertex(s, ch, false);
}

static uint32_t d3d_get_surface_pitch_z(NV15State *s, gf_channel *ch)
{
  if (s->card_type <= 0x35)
    return ch->d3d_surface_pitch_a >> 16;
  else
    return ch->d3d_surface_pitch_z;
}

/* ---- d3d method handlers ----------------------------------------------- */

static void d3d_mh_object(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  // There may be better place for initialization
  if (cls == 0x0096) {
    ch->d3d_window_offset_x = 2048;
    ch->d3d_window_offset_y = 2048;
    ch->d3d_attrib_count = 8;
  } else {
    ch->d3d_window_offset_x = 0;
    ch->d3d_window_offset_y = 0;
    ch->d3d_attrib_count = 16;
  }
  for (uint32_t j = 0; j < ch->d3d_attrib_count; j++) {
    ch->d3d_vertex_data_array_format_type[j] = 0;
    ch->d3d_vertex_data_array_format_size[j] = 0;
    ch->d3d_vertex_data_array_format_stride[j] = 0;
    ch->d3d_vertex_data_array_format_dx[j] = false;
    ch->d3d_vertex_data_array_format_homogeneous[j] = false;
  }
  if (cls == 0x0096)
    ch->d3d_vs_temp_regs_count = 0;
  else if (cls == 0x0097)
    ch->d3d_vs_temp_regs_count = 12;
  else if (cls <= 0x0497)
    ch->d3d_vs_temp_regs_count = 16;
  else
    ch->d3d_vs_temp_regs_count = 32;
  if (cls == 0x0096) {
    ch->d3d_combiner_control_num_stages = 2;
    ch->d3d_tex_coord_count = 2;
  } else if (cls == 0x0097) {
    ch->d3d_tex_coord_count = 4;
  } else {
    ch->d3d_tex_coord_count = 8;
  }
  if (cls == 0x0096) {
    ch->d3d_attrib_in_color[0] = 1;
    ch->d3d_attrib_in_color[1] = 2;
    ch->d3d_attrib_in_normal = 5;
  } else {
    ch->d3d_attrib_in_color[0] = 3;
    ch->d3d_attrib_in_color[1] = 4;
    ch->d3d_attrib_in_normal = 2;
  }
  ch->d3d_attrib_out_color[0] = 3;
  ch->d3d_attrib_out_color[1] = 4;
  ch->d3d_attrib_out_fogc = 5;
  for (uint32_t j = 0; j < 32; j++)
    ch->d3d_attrib_out_enable[j] = true;
  for (uint32_t j = 0; j < 16; j++) {
    ch->d3d_attrib_in_tex_coord[j] = 0xf;
    ch->d3d_attrib_out_tex_coord[j] = 0xf;
  }
  for (uint32_t j = 0; j < ch->d3d_tex_coord_count; j++) {
    if (cls == 0x0096)
      ch->d3d_attrib_in_tex_coord[j] = j + 3;
    else if (cls == 0x0097)
      ch->d3d_attrib_in_tex_coord[j] = j + 9;
    else
      ch->d3d_attrib_in_tex_coord[j] = j + 8;
    if (cls <= 0x0097)
      ch->d3d_attrib_out_tex_coord[j] = j + 9;
    else if (cls <= 0x0497)
      ch->d3d_attrib_out_tex_coord[j] = j + 8;
    else
      ch->d3d_attrib_out_tex_coord[j] = j + 7;
  }
  for (uint32_t ci = 0; ci < 4; ci++)
    ch->d3d_vertex_data_imm[ch->d3d_attrib_in_color[0]][ci] = 1.0f;
}

static void d3d_mh_flip_read(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  s->graph_flip_read = param;
}

static void d3d_mh_flip_write(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  s->graph_flip_write = param;
}

static void d3d_mh_flip_modulo(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  s->graph_flip_modulo = param;
}

static void d3d_mh_flip_incr(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  s->graph_flip_write++;
  if (s->graph_flip_modulo) {
    s->graph_flip_write %= s->graph_flip_modulo;
  }
}

static void d3d_mh_fifo_wait(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (s->graph_flip_read == s->graph_flip_write) {
    s->fifo_wait_flip = true;
    s->fifo_wait = true;
  }
}

static void d3d_mh_a_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_a_obj = param;
}

static void d3d_mh_b_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_b_obj = param;
}

static void d3d_mh_vertex_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_vertex_a_obj = param;
  ch->d3d_vertex_b_obj = param;
}

static void d3d_mh_color_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_color_obj = param;
}

static void d3d_mh_zeta_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_zeta_obj = param;
}

static void d3d_mh_vertex_a_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_vertex_a_obj = param;
}

static void d3d_mh_vertex_b_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_vertex_b_obj = param;
}

static void d3d_mh_semaphore_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_semaphore_obj = param;
}

static void d3d_mh_report_obj(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_report_obj = param;
}

static void d3d_mh_clip_horizontal(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_clip_horizontal = param;
}

static void d3d_mh_clip_vertical(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_clip_vertical = param;
}

static void d3d_mh_surface_format(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_surface_format = param;
  uint32_t format_color;
  uint32_t format_depth;
  if (cls <= 0x0097) {
    format_color = param & 0x0000000F;
    format_depth = (param >> 4) & 0x0000000F;
  } else {
    format_color = param & 0x0000001F;
    format_depth = (param >> 5) & 0x00000007;
  }
  if (format_color == 0x9)        // B8
    ch->d3d_color_bytes = 1;
  else if (format_color == 0x3)   // R5G6B5
    ch->d3d_color_bytes = 2;
  else if (format_color == 0x4 || // X8R8G8B8_Z8R8G8B8
           format_color == 0x5 || // X8R8G8B8_O8R8G8B8
           format_color == 0x8)   // A8R8G8B8
    ch->d3d_color_bytes = 4;
  else { }
  if (format_depth == 0)
    ch->d3d_depth_bytes = ch->d3d_color_bytes;
  else if (format_depth == 1) // Z16
    ch->d3d_depth_bytes = 2;
  else if (format_depth == 2) // Z24S8
    ch->d3d_depth_bytes = 4;
  else { }
  if (cls == 0x0096)
    ch->d3d_viewport_scale[2] = ch->d3d_depth_bytes == 2 ? 32767.0f : 8388607.0f;
}

static void d3d_mh_surface_pitch_a(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_surface_pitch_a = param;
}

static void d3d_mh_surface_color_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_surface_color_offset = param;
}

static void d3d_mh_surface_zeta_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_surface_zeta_offset = param;
}

static void d3d_mh_surface_pitch_z(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_surface_pitch_z = param;
}

static void d3d_mh_combiner_alpha_icw(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - 0x098;
  ch->d3d_combiner_alpha_icw[i] = param;
}

static void d3d_mh_combiner_final(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls <= 0x0097 ? 0x0a2 : 0x23d);
  ch->d3d_combiner_final[i] = param;
}

static void d3d_mh_0096_0a5(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_local_viewer = (param & 0x00010000) != 0;
}

static void d3d_mh_0096_0a6(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (cls == 0x0096) {
    ch->d3d_color_material_emission = (param >> 0) & 1;
    ch->d3d_color_material_ambient = (param >> 1) & 1;
    ch->d3d_color_material_diffuse = (param >> 2) & 1;
    ch->d3d_color_material_specular = (param >> 3) & 1;
  } else {
    ch->d3d_color_material_emission = (param >> 0) & 3;
    ch->d3d_color_material_ambient = (param >> 2) & 3;
    ch->d3d_color_material_diffuse = (param >> 4) & 3;
    ch->d3d_color_material_specular = (param >> 6) & 3;
  }
}

static void d3d_mh_fog_mode(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_fog_mode = param;
}

static void d3d_mh_fog_gen_mode(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_fog_gen_mode = param;
}

static void d3d_mh_fog_params(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 3;
  ch->d3d_fog_params[i] = uint32_as_float(param);
}

static void d3d_mh_fog_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_fog_enable = param;
}

static void d3d_mh_fog_color(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  for (uint32_t ci = 0; ci < 4; ci++)
    ch->d3d_fog_color[ci] = ((param >> (ci * 8)) & 0xff) / 255.0f;
}

static void d3d_mh_window_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_window_offset_x = (int16_t)param;
  ch->d3d_window_offset_y = (int16_t)(param >> 16);
}

static void d3d_mh_window_clip(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t index = (method >> 1) & 7;
  if ((method & 1) == 0) {
    ch->d3d_window_clip_x1[index] = param & 0x0000ffff;
    ch->d3d_window_clip_x2[index] = param >> 16;
  } else {
    ch->d3d_window_clip_y1[index] = param & 0x0000ffff;
    ch->d3d_window_clip_y2[index] = param >> 16;
  }
}

static void d3d_mh_alpha_test_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_alpha_test_enable = param;
}

static void d3d_mh_alpha_func(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_alpha_func = param;
}

static void d3d_mh_alpha_ref(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_alpha_ref = param;
}

static void d3d_mh_blend_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_enable = param;
}

static void d3d_mh_cull_face_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_cull_face_enable = param;
}

static void d3d_mh_depth_test_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_depth_test_enable = param;
}

static void d3d_mh_lighting_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_lighting_enable = param;
}

static void d3d_mh_stencil_test_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_test_enable = param;
}

static void d3d_mh_blend_sfactor_0096(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_sfactor_rgb = (uint16_t)param;
  ch->d3d_blend_sfactor_alpha = (uint16_t)param;
}

static void d3d_mh_blend_dfactor_0096(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_dfactor_rgb = (uint16_t)param;
  ch->d3d_blend_dfactor_alpha = (uint16_t)param;
}

static void d3d_mh_blend_equation_0096(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_equation_rgb = (uint16_t)param;
  ch->d3d_blend_equation_alpha = (uint16_t)param;
}

static void d3d_mh_blend_sfactor_0497(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_sfactor_rgb = (uint16_t)param;
  ch->d3d_blend_sfactor_alpha = param >> 16;
}

static void d3d_mh_blend_dfactor_0497(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_dfactor_rgb = (uint16_t)param;
  ch->d3d_blend_dfactor_alpha = param >> 16;
}

static void d3d_mh_blend_equation_0497(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_equation_rgb = (uint16_t)param;
  ch->d3d_blend_equation_alpha = param >> 16;
}

static void d3d_mh_blend_color(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_blend_color[0] = ((param >> 16) & 0xff) / 255.0f;
  ch->d3d_blend_color[1] = ((param >> 8) & 0xff) / 255.0f;
  ch->d3d_blend_color[2] = ((param >> 0) & 0xff) / 255.0f;
  ch->d3d_blend_color[3] = ((param >> 24) & 0xff) / 255.0f;
}

static void d3d_mh_depth_func(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_depth_func = param;
}

static void d3d_mh_color_mask(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_color_mask = param;
  ch->d3d_color_mask_565 = 0;
  ch->d3d_color_mask_8888 = 0;
  if (((param >> 0) & 1) != 0) {
    ch->d3d_color_mask_565 |= 0x001f;
    ch->d3d_color_mask_8888 |= 0x000000ff;
  }
  if (((param >> 8) & 1) != 0) {
    ch->d3d_color_mask_565 |= 0x07e0;
    ch->d3d_color_mask_8888 |= 0x0000ff00;
  }
  if (((param >> 16) & 1) != 0) {
    ch->d3d_color_mask_565 |= 0xf800;
    ch->d3d_color_mask_8888 |= 0x00ff0000;
  }
  if (((param >> 24) & 1) != 0)
    ch->d3d_color_mask_8888 |= 0xff000000;
}

static void d3d_mh_depth_write_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_depth_write_enable = param;
}

static void d3d_mh_stencil_mask(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_mask = param;
}

static void d3d_mh_stencil_func(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_func = param;
}

static void d3d_mh_stencil_func_ref(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_func_ref = param;
}

static void d3d_mh_stencil_func_mask(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_func_mask = param;
}

static void d3d_mh_0096_0dc(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_op_sfail = param;
}

static void d3d_mh_stencil_op_dpfail(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_op_dpfail = param;
}

static void d3d_mh_stencil_op_dppass(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_stencil_op_dppass = param;
}

static void d3d_mh_shade_mode(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_shade_mode = param;
}

static void d3d_mh_clip_min(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_clip_min = uint32_as_float(param);
}

static void d3d_mh_clip_max(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_clip_max = uint32_as_float(param);
}

static void d3d_mh_cull_face(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_cull_face = param;
}

static void d3d_mh_front_face(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_front_face = param;
}

static void d3d_mh_normalize_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_normalize_enable = param;
}

static void d3d_mh_material_factor(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - 0x0ea;
  ch->d3d_material_factor[i] = uint32_as_float(param);
}

static void d3d_mh_separate_specular(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_separate_specular = param & 1;
}

static void d3d_mh_light_enable_mask(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_light_enable_mask = param;
}

static void d3d_mh_texgen(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method - (cls <= 0x0097 ? 0x0f0 : 0x100);
  uint32_t tex_index = method_offset >> 2;
  uint32_t i = method_offset & 0x003;
  ch->d3d_texgen[tex_index][i] = param;
}

static void d3d_mh_texture_matrix_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x0f8 : (cls == 0x0097 ? 0x108 : 0x090));
  ch->d3d_texture_matrix_enable[i] = param;
}

static void d3d_mh_view_matrix_enable(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_view_matrix_enable = param;
}

static void d3d_mh_model_view_matrix(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x00f;
  uint32_t m = (method >> 4) & 1;
  ch->d3d_model_view_matrix[m][i] = uint32_as_float(param);
  if (s->card_type == 0x35)
    ch->d3d_transform_constant[0x44 + (i >> 2)][i & 3] = uint32_as_float(param);
}

static void d3d_mh_inverse_model_view_matrix(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x00f;
  ch->d3d_inverse_model_view_matrix[i] = uint32_as_float(param);
  if (s->card_type == 0x35)
    ch->d3d_transform_constant[0x48 + (i >> 2)][i & 3] = uint32_as_float(param);
}

static void d3d_mh_composite_matrix(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x00f;
  ch->d3d_composite_matrix[i] = uint32_as_float(param);
  if (s->card_type == 0x35)
    ch->d3d_transform_constant[0x3C + (i >> 2)][i & 3] = uint32_as_float(param);
}

static void d3d_mh_texture_matrix(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method - (cls == 0x0096 ? 0x150 : 0x1b0);
  uint32_t tex_index = method_offset >> 4;
  uint32_t i = method_offset & 0x00f;
  ch->d3d_texture_matrix[tex_index][i] = uint32_as_float(param);
  if (s->card_type == 0x35) {
    uint32_t const_ofs = i >> 2;
    if (tex_index <= 3)
      const_ofs += 0x80 + tex_index * 8;
    else
      const_ofs += 0x04 + (tex_index - 4) * 8;
    ch->d3d_transform_constant[const_ofs][i & 3] = uint32_as_float(param);
  }
}

static void d3d_mh_texgen_plane(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method - (cls == 0x0096 ? 0x180 : (cls == 0x0097 ? 0x210 : 0x380));
  uint32_t tex_index = method_offset >> 4;
  uint32_t tex_coord = (method_offset >> 2) & 3;
  uint32_t i = method_offset & 0x003;
  ch->d3d_texgen_plane[tex_index][tex_coord][i] = uint32_as_float(param);
}

static void d3d_mh_scissor_x_width(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_scissor_x = param & 0x0000ffff;
  ch->d3d_scissor_width = param >> 16;
}

static void d3d_mh_scissor_y_height(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_scissor_y = param & 0x0000ffff;
  ch->d3d_scissor_height = param >> 16;
}

static void d3d_mh_shader_program(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_shader_program = param;
  ch->d3d_shader_offset = ch->d3d_shader_program & ~3;
  uint32_t location = ch->d3d_shader_program & 3;
  if (location == 1)
    ch->d3d_shader_obj = ch->d3d_a_obj;
  else if (location == 2)
    ch->d3d_shader_obj = ch->d3d_b_obj;
  else
    ch->d3d_shader_obj = 0;
}

static void d3d_mh_0497_240(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t stage = (method >> 3) & 7;
  uint32_t rc_method = method & 7;
  if (rc_method == 0)
    ch->d3d_combiner_alpha_icw[stage] = param;
  else if (rc_method == 1)
    ch->d3d_combiner_color_icw[stage] = param;
  else if (rc_method == 2 || rc_method == 3) {
    uint32_t i = rc_method - 2;
    ch->d3d_combiner_const_color[stage][i][0] = ((param >> 16) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[stage][i][1] = ((param >> 8) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[stage][i][2] = ((param >> 0) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[stage][i][3] = ((param >> 24) & 0xff) / 255.0f;
  } else if (rc_method == 4)
    ch->d3d_combiner_alpha_ocw[stage] = param;
  else if (rc_method == 5)
    ch->d3d_combiner_color_ocw[stage] = param;
}

static void d3d_mh_viewport_x_width(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_viewport_x = param & 0x0000ffff;
  ch->d3d_viewport_width = param >> 16;
}

static void d3d_mh_viewport_y_height(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_viewport_y = param & 0x0000ffff;
  ch->d3d_viewport_height = param >> 16;
}

static void d3d_mh_specular_params(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 7;
  ch->d3d_specular_params[i] = uint32_as_float(param);
  if (i == 5) {
    // Very rough approximation
    if (ch->d3d_specular_params[0] > -0.2f)
      ch->d3d_specular_power = ch->d3d_specular_params[2];
    else {
      ch->d3d_specular_power = 1.0f / (1.0f + ch->d3d_specular_params[0]);
      ch->d3d_specular_power = ch->d3d_specular_power *
        (2.7f + 0.25f * log(ch->d3d_specular_power)) - 1.0f;
    }
  }
}

static void d3d_mh_scene_ambient_color(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x1b1 : 0x284);
  ch->d3d_scene_ambient_color[i] = uint32_as_float(param);
}

static void d3d_mh_viewport_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x1ba : 0x288);
  ch->d3d_viewport_offset[i] = uint32_as_float(param);
  if (s->card_type == 0x20)
    ch->d3d_transform_constant[0x3b][i] = uint32_as_float(param);
  else if (s->card_type == 0x35)
    ch->d3d_transform_constant[0x77][i] = uint32_as_float(param);
}

static void d3d_mh_eye_position(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - 0x294;
  ch->d3d_eye_position[i] = uint32_as_float(param);
}

static void d3d_mh_0096_09c(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 1;
  for (uint32_t s2 = 0; s2 < 2; s2++) {
    ch->d3d_combiner_const_color[s2][i][0] = ((param >> 16) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[s2][i][1] = ((param >> 8) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[s2][i][2] = ((param >> 0) & 0xff) / 255.0f;
    ch->d3d_combiner_const_color[s2][i][3] = ((param >> 24) & 0xff) / 255.0f;
  }
}

static void d3d_mh_0097_298(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method - 0x298;
  uint32_t s2 = method_offset & 7;
  uint32_t i = method_offset >> 3;
  ch->d3d_combiner_const_color[s2][i][0] = ((param >> 16) & 0xff) / 255.0f;
  ch->d3d_combiner_const_color[s2][i][1] = ((param >> 8) & 0xff) / 255.0f;
  ch->d3d_combiner_const_color[s2][i][2] = ((param >> 0) & 0xff) / 255.0f;
  ch->d3d_combiner_const_color[s2][i][3] = ((param >> 24) & 0xff) / 255.0f;
}

static void d3d_mh_combiner_alpha_ocw(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x09e : 0x2a8);
  ch->d3d_combiner_alpha_ocw[i] = param;
}

static void d3d_mh_combiner_color_icw(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x09a : 0x2b0);
  ch->d3d_combiner_color_icw[i] = param;
}

static void d3d_mh_texture_key_color(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t texture_index = method - (cls == 0x0097 ? 0x2b8 : 0x740);
  ch->d3d_texture[texture_index].key_color = param;
}

static void d3d_mh_viewport_scale(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_viewport_scale[i] = uint32_as_float(param);
  if (s->card_type == 0x20)
    ch->d3d_transform_constant[0x3a][i] = uint32_as_float(param);
  else if (s->card_type == 0x35)
    ch->d3d_transform_constant[0x76][i] = uint32_as_float(param);
}

static void d3d_mh_transform_program(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_transform_program[ch->d3d_transform_program_load][i] = param;
  if (i == 3)
    ch->d3d_transform_program_load++;
}

static void d3d_mh_transform_constant(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_transform_constant[
    ch->d3d_transform_constant_load][i] = uint32_as_float(param);
  if (i == 3)
    ch->d3d_transform_constant_load++;
}

static void d3d_mh_light(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t light_index;
  uint32_t light_method;
  if (cls <= 0x0097) {
    light_index = (method >> 5) & 7;
    light_method = method & 0x01f;
  } else {
    light_index = (method >> 4) & 7;
    light_method = (method & 0x00f) | ((method & 0x080) >> 3);
  }
  gf_light *light = &ch->d3d_light[light_index];
  if (light_method <= 0x02) {
    light->ambient_color[light_method] = uint32_as_float(param);
  } else if (light_method >= 0x03 && light_method <= 0x05) {
    uint32_t i = light_method - 0x03;
    light->diffuse_color[i] = uint32_as_float(param);
  } else if (light_method >= 0x06 && light_method <= 0x08) {
    uint32_t i = light_method - 0x06;
    light->specular_color[i] = uint32_as_float(param);
  } else if (light_method >= 0x0a && light_method <= 0x0c) {
    uint32_t i = light_method - 0x0a;
    light->inf_half_vector[i] = uint32_as_float(param);
    if (s->card_type == 0x35)
      ch->d3d_transform_constant[0x30 + light_index][i] = uint32_as_float(param);
  } else if (light_method >= 0x0d && light_method <= 0x0f) {
    uint32_t i = light_method - 0x0d;
    light->inf_direction[i] = uint32_as_float(param);
  } else if (light_method >= 0x13 && light_method <= 0x16) {
    uint32_t i = light_method - 0x13;
    light->spot_direction[i] = uint32_as_float(param);
  } else if (light_method >= 0x17 && light_method <= 0x19) {
    uint32_t i = light_method - 0x17;
    light->local_position[i] = uint32_as_float(param);
    if (s->card_type == 0x35)
      ch->d3d_transform_constant[0x64 + light_index][i] = uint32_as_float(param);
  } else if (light_method >= 0x1a && light_method <= 0x1c) {
    uint32_t i = light_method - 0x1a;
    light->local_attenuation[i] = uint32_as_float(param);
    if (s->card_type == 0x35)
      ch->d3d_transform_constant[0x30 + light_index][i] = uint32_as_float(param);
  }
}

static void d3d_mh_0096_300(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t comp_index = method & 0x003;
  ch->d3d_vertex_data_imm[0][comp_index] = uint32_as_float(param);
  if (comp_index == 2) {
    ch->d3d_vertex_data_imm[0][3] = 1.0f;
    d3d_process_vertex(s, ch, true);
  }
}

static void d3d_mh_0497_540(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t comp_index = method & 0x003;
  if (comp_index != 3) {
    uint32_t attrib_index = (method >> 2) & 0xf;
    ch->d3d_vertex_data_imm[attrib_index][comp_index] = uint32_as_float(param);
    if (comp_index == 2) {
      ch->d3d_vertex_data_imm[attrib_index][3] = 1.0f;
      if (attrib_index == 0)
        d3d_process_vertex(s, ch, true);
    }
  }
}

static void d3d_mh_0096_306(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x306 : 0x546);
  ch->d3d_vertex_data_imm[0][i] = uint32_as_float(param);
  if (i == 3)
    d3d_process_vertex(s, ch, true);
}

static void d3d_mh_0096_30c(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_vertex_data_imm[ch->d3d_attrib_in_normal][i] = uint32_as_float(param);
}

static void d3d_mh_0096_314(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_vertex_data_imm[ch->d3d_attrib_in_color[0]][i] = uint32_as_float(param);
}

static void d3d_mh_0096_318(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method & 0x003;
  ch->d3d_vertex_data_imm[ch->d3d_attrib_in_color[0]][i] = uint32_as_float(param);
  if (i == 2)
    ch->d3d_vertex_data_imm[ch->d3d_attrib_in_color[0]][3] = 1.0f;
}

static void d3d_mh_0096_31b(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  unpack_attribute(param, false,
    ch->d3d_vertex_data_imm[ch->d3d_attrib_in_color[0]]);
}

static void d3d_mh_texcoord(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method - (cls == 0x0096 ? 0x324 : 0x564);
  uint32_t texcoord_index = method_offset / 10;
  uint32_t texcoord_method = method_offset % 10;
  float *texcoord = ch->d3d_vertex_data_imm[
    ch->d3d_attrib_in_tex_coord[texcoord_index]];
  // TEXCOORD3_4F/4S may require special handling
  if (texcoord_method <= 1) {
    if (texcoord_method == 1) {
      texcoord[2] = 0.0f;
      texcoord[3] = 1.0f;
    }
    texcoord[texcoord_method] = uint32_as_float(param);
  } else if (texcoord_method == 2) {
    texcoord[0] = (int16_t)(param & 0xffff);
    texcoord[1] = (int16_t)(param >> 16);
    texcoord[2] = 0.0f;
    texcoord[3] = 1.0f;
  } else if (texcoord_method >= 4 && texcoord_method <= 7)
    texcoord[texcoord_method - 4] = uint32_as_float(param);
}

static void d3d_mh_0097_5c8(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0097 ? 0x5c8 : 0x5a0);
  ch->d3d_vertex_data_array_offset[i] = param;
}

static void d3d_mh_vertex_data_base_index(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_vertex_data_base_index = param;
}

static void d3d_mh_vertex_data_array_format(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i;
  if (cls == 0x0096) {
    uint32_t method_offset = method - 0x340;
    i = method_offset >> 1;
    if ((method_offset & 1) == 0) {
      ch->d3d_vertex_data_array_offset[i] = param;
      return;
    }
  } else {
    i = method - (cls == 0x0097 ? 0x5d8 : 0x5d0);
  }
  ch->d3d_vertex_data_array_format_stride[i] = (param >> 8) & 0xff;
  ch->d3d_vertex_data_array_format_dx[i] = (param & 0x00010000) != 0;
  ch->d3d_vertex_data_array_format_homogeneous[i] = (param & 0x01000000) != 0;
  if (!ch->d3d_vertex_data_array_format_dx[i]) {
    ch->d3d_vertex_data_array_format_type[i] = param & 0xf;
    ch->d3d_vertex_data_array_format_size[i] = (param >> 4) & 0xf;
  } else {
    uint32_t dxtype = param & 0xff;
    if (dxtype == 0x44) {
      ch->d3d_vertex_data_array_format_type[i] = 4;
      ch->d3d_vertex_data_array_format_size[i] = 4;
    } else if (dxtype == 0x88) {
      ch->d3d_vertex_data_array_format_type[i] = 2;
      ch->d3d_vertex_data_array_format_size[i] = 1;
    } else if (dxtype == 0x99) {
      ch->d3d_vertex_data_array_format_type[i] = 2;
      ch->d3d_vertex_data_array_format_size[i] = 2;
    } else if (dxtype == 0xaa) {
      ch->d3d_vertex_data_array_format_type[i] = 2;
      ch->d3d_vertex_data_array_format_size[i] = 3;
    } else if (dxtype == 0xbb) {
      ch->d3d_vertex_data_array_format_type[i] = 2;
      ch->d3d_vertex_data_array_format_size[i] = 4;
    } else if (dxtype == 0xcc) {
      ch->d3d_vertex_data_array_format_type[i] = 0;
      ch->d3d_vertex_data_array_format_size[i] = 4;
    } else if (dxtype == 0xee) {
      ch->d3d_vertex_data_array_format_type[i] = 5;
      ch->d3d_vertex_data_array_format_size[i] = 2;
    }
  }
}

static void d3d_mh_get_report(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t offset = param & 0x00ffffff;
  nv_dma_write64(s, ch->d3d_report_obj, offset + 0x0, nv_get_current_time(s));
  nv_dma_write32(s, ch->d3d_report_obj, offset + 0x8, 0);
  nv_dma_write32(s, ch->d3d_report_obj, offset + 0xC, 0);
}

static void d3d_mh_begin_end(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (param != 0) {
    ch->d3d_primitive_done = false;
    ch->d3d_triangle_flip = false;
    ch->d3d_vertex_index = 0;
    ch->d3d_attrib_index = cls == 0x0096 ? 7 : 0;
    ch->d3d_comp_index = 0;
  }
  ch->d3d_begin_end = param;
}

static void d3d_mh_array_element16(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  d3d_load_vertex(s, ch, param & 0x0000ffff);
  d3d_load_vertex(s, ch, param >> 16);
}

static void d3d_mh_array_element32(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  d3d_load_vertex(s, ch, param);
}

static void d3d_mh_draw_arrays(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t vertex_first = param & 0x00ffffff;
  uint32_t vertex_last = vertex_first + (param >> 24);
  for (uint32_t v = vertex_first; v <= vertex_last; v++)
    d3d_load_vertex(s, ch, v);
}

static void d3d_mh_inline_array(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (cls == 0x0096)
    while (ch->d3d_attrib_index < 16 &&
           ch->d3d_vertex_data_array_format_size[ch->d3d_attrib_index] == 0) {
      for (uint32_t ci = 0; ci < 4; ci++) {
        ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][ci] =
          ch->d3d_vertex_data_imm[ch->d3d_attrib_index][ci];
      }
      /* Stop before d3d_attrib_index (uint32_t) underflows to ~0u, which
       * would index d3d_vertex_data_array_format_size[] and the vertex
       * arrays far out of bounds. */
      if (ch->d3d_attrib_index == 0) {
        break;
      }
      ch->d3d_attrib_index--;
    }
  if (ch->d3d_comp_index == 0) {
    ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][2] = 0.0f;
    ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][3] = 1.0f;
  }
  uint32_t format_type = ch->d3d_vertex_data_array_format_type[ch->d3d_attrib_index];
  if ((format_type == 0 || format_type == 4) &&
      ch->d3d_vertex_data_array_format_size[ch->d3d_attrib_index] == 4) {
    unpack_attribute(param, format_type == 0,
      ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index]);
    ch->d3d_comp_index = 4;
  } else if (format_type == 5 && ch->d3d_vertex_data_array_format_size[ch->d3d_attrib_index] == 2) {
    ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][0] = (float)(int16_t)param;
    ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][1] = (float)(int16_t)(param >> 16);
    ch->d3d_comp_index = 2;
  } else {
    ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][
      ch->d3d_comp_index++] = uint32_as_float(param);
  }
  bool process = false;
  while (ch->d3d_comp_index ==
         ch->d3d_vertex_data_array_format_size[ch->d3d_attrib_index]) {
    if (ch->d3d_comp_index == 0) {
      for (uint32_t ci = 0; ci < 4; ci++) {
        ch->d3d_vertex_data[ch->d3d_vertex_index][ch->d3d_attrib_index][ci] =
          ch->d3d_vertex_data_imm[ch->d3d_attrib_index][ci];
      }
    } else {
      ch->d3d_comp_index = 0;
    }
    if (cls == 0x0096) {
      if (ch->d3d_attrib_index == 0) {
        ch->d3d_attrib_index = 7;
        process = true;
        break;
      } else {
        ch->d3d_attrib_index--;
      }
    } else {
      if (ch->d3d_attrib_index == 15) {
        ch->d3d_attrib_index = 0;
        process = true;
        break;
      } else {
        ch->d3d_attrib_index++;
      }
    }
  }
  if (process)
    d3d_process_vertex(s, ch, false);
}

static void d3d_mh_index_array_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_index_array_offset = param;
}

static void d3d_mh_index_array_dma(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_index_array_dma = (param & 1) != 0;
  ch->d3d_index_array_type_16 = ((param >> 4) & 1) != 0;
}

static void d3d_mh_0497_609(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t vertex_first = param & 0x00ffffff;
  uint32_t vertex_last = vertex_first + (param >> 24);
  uint32_t index_array_obj = ch->d3d_index_array_dma ?
    ch->d3d_vertex_b_obj : ch->d3d_vertex_a_obj;
  for (uint32_t v = vertex_first; v <= vertex_last; v++) {
    uint32_t vertex_array_index;
    if (ch->d3d_index_array_type_16)
      vertex_array_index = nv_dma_read16(s, index_array_obj, ch->d3d_index_array_offset + v * 2);
    else
      vertex_array_index = nv_dma_read32(s, index_array_obj, ch->d3d_index_array_offset + v * 4);
    d3d_load_vertex(s, ch, vertex_array_index);
  }
}

static void d3d_mh_0097_60a(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (ch->d3d_vertex_index != 2) {
    for (uint32_t ai = 0; ai < ch->d3d_attrib_count; ai++) {
      for (uint32_t ci = 0; ci < 4; ci++) {
        ch->d3d_vertex_data[ch->d3d_vertex_index][ai][ci] =
          ch->d3d_vertex_data[2 - (param & 1)][ai][ci];
      }
    }
  }
  d3d_process_vertex(s, ch, false);
}

static void d3d_mh_0497_610(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t texture_index = method & 0x00f;
  gf_texture *tex = &ch->d3d_texture[texture_index];
  if (cls == 0x0497) {
    tex->pal_dma_obj = (param & 1) == 1 ? ch->d3d_b_obj : ch->d3d_a_obj;
    tex->pal_ofs = param & 0xffffffc0;
  } else
    tex->control3 = param;
}

static void d3d_mh_0097_620(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t comp_index = method & 1;
  uint32_t attrib_index = (method >> 1) & 0xf;
  ch->d3d_vertex_data_imm[attrib_index][comp_index] = uint32_as_float(param);
  if (comp_index == 1) {
    ch->d3d_vertex_data_imm[attrib_index][2] = 0.0f;
    ch->d3d_vertex_data_imm[attrib_index][3] = 1.0f;
    if (attrib_index == 0)
      d3d_process_vertex(s, ch, true);
  }
}

static void d3d_mh_0097_640(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t attrib_index = method & 0xf;
  ch->d3d_vertex_data_imm[attrib_index][0] = (int16_t)(param & 0xffff);
  ch->d3d_vertex_data_imm[attrib_index][1] = (int16_t)(param >> 16);
  ch->d3d_vertex_data_imm[attrib_index][2] = 0.0f;
  ch->d3d_vertex_data_imm[attrib_index][3] = 1.0f;
  if (attrib_index == 0)
    d3d_process_vertex(s, ch, true);
}

static void d3d_mh_0097_650(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t attrib_index = method & 0xf;
  unpack_attribute(param, false, ch->d3d_vertex_data_imm[attrib_index]);
  if (attrib_index == 0)
    d3d_process_vertex(s, ch, true);
}

static void d3d_mh_0097_680(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t comp_index = method & 3;
  uint32_t attrib_index = (method >> 2) & 0xf;
  ch->d3d_vertex_data_imm[attrib_index][comp_index] = uint32_as_float(param);
  if (comp_index == 3 && attrib_index == 0)
    d3d_process_vertex(s, ch, true);
}

static void d3d_mh_texture(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t method_offset = method -
    (cls == 0x0096 ? 0x086 : (cls == 0x0097 ? 0x6c0 : 0x680));
  uint32_t texture_index;
  uint32_t texture_method;
  if (cls == 0x0096) {
    texture_index = method_offset & 1;
    texture_method = method_offset >> 1;
  } else {
    texture_index = method_offset >> (cls == 0x0097 ? 4 : 3);
    texture_method = method_offset & (cls == 0x0097 ? 0xf : 7);
  }
  gf_texture *tex = &ch->d3d_texture[texture_index];
  if (texture_method == 0)
    tex->offset = param;
  else if (texture_method == 1) {
    tex->dma_obj = (param & 3) == 1 ? ch->d3d_a_obj : ch->d3d_b_obj;
    tex->cubemap = (param & 4) != 0;
    if (cls == 0x0096) {
      tex->format = (param >> 7) & 0x1f;
      tex->levels = (param >> 12) & 0xf;
      tex->base_size[0] = (param >> 16) & 0xf;
      tex->base_size[1] = (param >> 20) & 0xf;
      tex->wrap[0] = (param >> 24) & 0xf;
      tex->wrap[1] = (param >> 28) & 0xf;
    } else {
      tex->format = (param >> 8) & 0xff;
      tex->levels = (param >> 16) & 0xf;
      tex->base_size[0] = (param >> 20) & 0xf;
      tex->base_size[1] = (param >> 24) & 0xf;
      tex->base_size[2] = (param >> 28) & 0xf;
    }
    d3d_texture_process_format(s, tex);
    texture_update_size(tex, cls);
  } else if (texture_method == 2 && cls != 0x0096) {
    tex->wrap[0] = (param >> 0) & 0xf;
    tex->wrap[1] = (param >> 8) & 0xf;
    tex->wrap[2] = (param >> 16) & 0xf;
  } else if ((texture_method == 2 && cls == 0x0096) ||
             (texture_method == 3 && cls != 0x0096)) {
    tex->control0 = param;
    if (cls == 0x4097)
      tex->enabled = param >> 31;
    else
      tex->enabled = (param >> 30) & 1;
    if (cls == 0x0096)
      ch->d3d_tex_shader_op[texture_index] = tex->enabled ? 0x01 : 0x00;
  } else if ((texture_method == 3 && cls == 0x0096) ||
             (texture_method == 4 && cls != 0x0096)) {
    tex->control1 = param;
  } else if ((texture_method == 6 && cls == 0x0096) ||
             (texture_method == 5 && cls != 0x0096)) {
    // filtering is not implemented
    if (cls != 0x0096) {
      uint32_t signed_argb = param >> 28;
      tex->signed_any = signed_argb != 0;
      for (uint32_t i = 0; i < 4; i++)
        tex->signed_comp[i] = (signed_argb & (1 << i)) != 0;
    } else {
      tex->signed_any = false;
    }
  } else if ((texture_method == 5 && cls == 0x0096) ||
             (texture_method == 7 && cls == 0x0097) ||
             (texture_method == 6 && cls >= 0x0497)) {
    tex->image_rect = param;
    texture_update_size(tex, cls);
  } else if ((texture_method == 7 && cls == 0x0096) ||
             (texture_method == 8 && cls == 0x0097)) {
    tex->pal_dma_obj = (param & 1) == 1 ? ch->d3d_b_obj : ch->d3d_a_obj;
    tex->pal_ofs = param & 0xffffffc0;
  } else if (texture_method >= 10 && texture_method <= 13 && cls == 0x0097) {
    tex->offset_matrix[texture_method - 10] = uint32_as_float(param);
  }
}

static void d3d_mh_shader_control(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_shader_control = param;
}

static void d3d_mh_semaphore_offset(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_semaphore_offset = param;
}

static void d3d_mh_75c(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  nv_dma_write32(s, ch->d3d_semaphore_obj, ch->d3d_semaphore_offset, param);
}

static void d3d_mh_75d(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  // Semaphore release mechanism should be used instead
  s->crtc_start = param;
  s->svga_needs_update_mode = 1;
}

static void d3d_mh_zstencil_clear_value(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_zstencil_clear_value = param;
}

static void d3d_mh_color_clear_value(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_color_clear_value = param;
}

static void d3d_mh_clear_surface(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_clear_surface = param;
  d3d_clear_surface(s, ch);
}

static void d3d_mh_combiner_color_ocw(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  uint32_t i = method - (cls == 0x0096 ? 0x0a0 : 0x790);
  ch->d3d_combiner_color_ocw[i] = param;
}

static void d3d_mh_combiner_control(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_combiner_control = param;
  ch->d3d_combiner_control_num_stages = param & 0xf;
}

static void d3d_mh_tex_shader_op(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  for (uint32_t i = 0; i < 4; i++)
    ch->d3d_tex_shader_op[i] = (param >> (i * 5)) & 0x1f;
}

static void d3d_mh_tex_shader_dotmapping(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_tex_shader_dotmapping[1] = (param >> 0) & 0xf;
  ch->d3d_tex_shader_dotmapping[2] = (param >> 4) & 0xf;
  ch->d3d_tex_shader_dotmapping[3] = (param >> 8) & 0xf;
}

static void d3d_mh_tex_shader_previous(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_tex_shader_previous[2] = (param >> 16) & 3;
  ch->d3d_tex_shader_previous[3] = (param >> 20) & 3;
}

static void d3d_mh_transform_execution_mode(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_transform_execution_mode = param;
}

static void d3d_mh_transform_program_load(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_transform_program_load = param;
}

static void d3d_mh_transform_program_start(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_transform_program_start = param;
}

static void d3d_mh_transform_constant_load(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_transform_constant_load = param;
}

static void d3d_mh_4097_7f1(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  ch->d3d_attrib_out_color[0] = param & 0xf;
  ch->d3d_attrib_out_color[1] = (param >> 4) & 0xf;
  ch->d3d_attrib_out_fogc = (param >> 24) == 6 ? 5 : 1; // hack
}

static void d3d_mh_4097_7f2(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  for (uint32_t i = 0; i < 8; i++)
    ch->d3d_attrib_out_tex_coord[i] = (param >> (i * 4)) & 0xf;
}

static void d3d_mh_4097_7f3(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  for (uint32_t i = 0; i < 2; i++)
    ch->d3d_attrib_out_tex_coord[i + 8] = (param >> (i * 4)) & 0xf;
}

static void d3d_mh_4097_7fd(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  for (uint32_t i = 0; i < 32; i++)
    ch->d3d_attrib_out_enable[i] = (bool)((param >> i) & 1);
  ch->d3d_fog_enable = ch->d3d_attrib_out_enable[4];
}

/* ---- dispatch scaffolding (NV15-only, class 0x0096) -------------------- */

static void empty_method_handler(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param) {}

static void set_mh(NV15State *s, uint32_t cls, uint32_t method, gf_method_handler h) {
    if (cls != 0x0096 || method >= GEFORCE_METHOD_COUNT) return;
    s->cl0096_method_handlers[method] = h;
}

static void set_mh_range(NV15State *s, uint32_t cls, uint32_t ms, uint32_t me, gf_method_handler h) {
    for (uint32_t i = ms; i <= me; i++) set_mh(s, cls, i, h);
}

static void set_d3d_mh1(NV15State *s, int c96, int c97, int c497, int c4097, uint32_t m, gf_method_handler h) {
    if (c96) set_mh(s, 0x0096, m, h);
}

static void set_d3d_mh(NV15State *s, int c96, int c97, int c497, int c4097, uint32_t ms, uint32_t me, gf_method_handler h) {
    if (c96) set_mh_range(s, 0x0096, ms, me, h);
}

void nv3d_init_method_handlers(NV15State *s)
{
  for (int i = 0; i < GEFORCE_METHOD_COUNT; i++) {
    s->empty_method_handlers[i] = empty_method_handler;
    s->cl0096_method_handlers[i] = empty_method_handler;
  }
  for (int i = 0; i < GEFORCE_CLASS_COUNT; i++)
    s->class_method_handlers[i] = s->empty_method_handlers;
  s->class_method_handlers[0x0096] = s->cl0096_method_handlers;

  set_d3d_mh1(s, 1, 1, 1, 1, 0x000, d3d_mh_object);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x048, d3d_mh_flip_read);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x049, d3d_mh_flip_write);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x04a, d3d_mh_flip_modulo);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x04b, d3d_mh_flip_incr);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x04c, d3d_mh_fifo_wait);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x061, d3d_mh_a_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x062, d3d_mh_b_obj);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x063, d3d_mh_vertex_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x065, d3d_mh_color_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x066, d3d_mh_zeta_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x067, d3d_mh_vertex_a_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x068, d3d_mh_vertex_b_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x069, d3d_mh_semaphore_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x06a, d3d_mh_report_obj);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x080, d3d_mh_clip_horizontal);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x081, d3d_mh_clip_vertical);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x082, d3d_mh_surface_format);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x083, d3d_mh_surface_pitch_a);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x084, d3d_mh_surface_color_offset);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x085, d3d_mh_surface_zeta_offset);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x08b, d3d_mh_surface_pitch_z);
  set_d3d_mh(s, 1, 0, 0, 0, 0x098, 0x099, d3d_mh_combiner_alpha_icw);
  set_d3d_mh(s, 0, 1, 0, 0, 0x098, 0x09f, d3d_mh_combiner_alpha_icw);
  set_d3d_mh(s, 1, 1, 0, 0, 0x0a2, 0x0a3, d3d_mh_combiner_final);
  set_d3d_mh(s, 0, 0, 1, 0, 0x23d, 0x23e, d3d_mh_combiner_final);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0a5, d3d_mh_0096_0a5);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x509, d3d_mh_0096_0a5);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0a6, d3d_mh_0096_0a6);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0e4, d3d_mh_0096_0a6);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0a7, d3d_mh_fog_mode);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x233, d3d_mh_fog_mode);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0a8, d3d_mh_fog_gen_mode);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x232, d3d_mh_fog_gen_mode);
  set_d3d_mh(s, 1, 0, 0, 0, 0x1a0, 0x1a2, d3d_mh_fog_params);
  set_d3d_mh(s, 0, 1, 0, 0, 0x270, 0x272, d3d_mh_fog_params);
  set_d3d_mh(s, 0, 0, 1, 1, 0x234, 0x236, d3d_mh_fog_params);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0a9, d3d_mh_fog_enable);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x0db, d3d_mh_fog_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0aa, d3d_mh_fog_color);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x0dc, d3d_mh_fog_color);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0ae, d3d_mh_window_offset);
  set_d3d_mh(s, 0, 0, 1, 1, 0x0b0, 0x0bf, d3d_mh_window_clip);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0c0, d3d_mh_alpha_test_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c1, d3d_mh_alpha_test_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0cf, d3d_mh_alpha_func);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c2, d3d_mh_alpha_func);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d0, d3d_mh_alpha_ref);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c3, d3d_mh_alpha_ref);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0c1, d3d_mh_blend_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c4, d3d_mh_blend_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0c2, d3d_mh_cull_face_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x60f, d3d_mh_cull_face_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0c3, d3d_mh_depth_test_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x29d, d3d_mh_depth_test_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0c5, d3d_mh_lighting_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x516, d3d_mh_lighting_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0cb, d3d_mh_stencil_test_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0ca, d3d_mh_stencil_test_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d1, d3d_mh_blend_sfactor_0096);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d2, d3d_mh_blend_dfactor_0096);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d4, d3d_mh_blend_equation_0096);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c5, d3d_mh_blend_sfactor_0497);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c6, d3d_mh_blend_dfactor_0497);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c8, d3d_mh_blend_equation_0497);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d3, d3d_mh_blend_color);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c7, d3d_mh_blend_color);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d5, d3d_mh_depth_func);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x29b, d3d_mh_depth_func);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d6, d3d_mh_color_mask);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0c9, d3d_mh_color_mask);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d7, d3d_mh_depth_write_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x29c, d3d_mh_depth_write_enable);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d8, d3d_mh_stencil_mask);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0cb, d3d_mh_stencil_mask);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0d9, d3d_mh_stencil_func);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0cc, d3d_mh_stencil_func);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0da, d3d_mh_stencil_func_ref);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0cd, d3d_mh_stencil_func_ref);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0db, d3d_mh_stencil_func_mask);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0ce, d3d_mh_stencil_func_mask);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0dc, d3d_mh_0096_0dc);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0cf, d3d_mh_0096_0dc);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0dd, d3d_mh_stencil_op_dpfail);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0d0, d3d_mh_stencil_op_dpfail);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0de, d3d_mh_stencil_op_dppass);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0d1, d3d_mh_stencil_op_dppass);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0df, d3d_mh_shade_mode);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0da, d3d_mh_shade_mode);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x0e5, d3d_mh_clip_min);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x0e6, d3d_mh_clip_max);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0e7, d3d_mh_cull_face);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x60c, d3d_mh_cull_face);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0e8, d3d_mh_front_face);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x60d, d3d_mh_front_face);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0e9, d3d_mh_normalize_enable);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x0df, d3d_mh_normalize_enable);
  set_d3d_mh(s, 1, 1, 0, 0, 0x0ea, 0x0ed, d3d_mh_material_factor);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x0ed, d3d_mh_material_factor);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0ee, d3d_mh_separate_specular);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x50a, d3d_mh_separate_specular);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x0ef, d3d_mh_light_enable_mask);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x508, d3d_mh_light_enable_mask);
  set_d3d_mh(s, 1, 0, 0, 0, 0x0f0, 0x0f7, d3d_mh_texgen);
  set_d3d_mh(s, 0, 1, 0, 0, 0x0f0, 0x0ff, d3d_mh_texgen);
  set_d3d_mh(s, 0, 0, 1, 0, 0x100, 0x11f, d3d_mh_texgen);
  set_d3d_mh(s, 1, 0, 0, 0, 0x0f8, 0x0f9, d3d_mh_texture_matrix_enable);
  set_d3d_mh(s, 0, 1, 0, 0, 0x108, 0x10b, d3d_mh_texture_matrix_enable);
  set_d3d_mh(s, 0, 0, 1, 0, 0x090, 0x097, d3d_mh_texture_matrix_enable);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x0fa, d3d_mh_view_matrix_enable);
  set_d3d_mh(s, 1, 0, 0, 0, 0x100, 0x11f, d3d_mh_model_view_matrix);
  set_d3d_mh(s, 0, 1, 1, 0, 0x120, 0x13f, d3d_mh_model_view_matrix);
  set_d3d_mh(s, 1, 0, 0, 0, 0x120, 0x12b, d3d_mh_inverse_model_view_matrix);
  set_d3d_mh(s, 0, 1, 1, 0, 0x160, 0x16b, d3d_mh_inverse_model_view_matrix);
  set_d3d_mh(s, 1, 0, 0, 0, 0x140, 0x14f, d3d_mh_composite_matrix);
  set_d3d_mh(s, 0, 1, 1, 0, 0x1a0, 0x1af, d3d_mh_composite_matrix);
  set_d3d_mh(s, 1, 0, 0, 0, 0x150, 0x16f, d3d_mh_texture_matrix);
  set_d3d_mh(s, 0, 1, 0, 0, 0x1b0, 0x1ef, d3d_mh_texture_matrix);
  set_d3d_mh(s, 0, 0, 1, 0, 0x1b0, 0x22f, d3d_mh_texture_matrix);
  set_d3d_mh(s, 1, 0, 0, 0, 0x180, 0x19f, d3d_mh_texgen_plane);
  set_d3d_mh(s, 0, 1, 0, 0, 0x210, 0x24f, d3d_mh_texgen_plane);
  set_d3d_mh(s, 0, 0, 1, 0, 0x380, 0x3ff, d3d_mh_texgen_plane);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x230, d3d_mh_scissor_x_width);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x231, d3d_mh_scissor_y_height);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x239, d3d_mh_shader_program);
  set_d3d_mh(s, 0, 0, 1, 0, 0x240, 0x27f, d3d_mh_0497_240);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x280, d3d_mh_viewport_x_width);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x281, d3d_mh_viewport_y_height);
  set_d3d_mh(s, 1, 0, 0, 0, 0x1a8, 0x1ad, d3d_mh_specular_params);
  set_d3d_mh(s, 0, 1, 0, 0, 0x278, 0x27d, d3d_mh_specular_params);
  set_d3d_mh(s, 0, 0, 1, 0, 0x500, 0x505, d3d_mh_specular_params);
  set_d3d_mh(s, 1, 0, 0, 0, 0x1b1, 0x1b3, d3d_mh_scene_ambient_color);
  set_d3d_mh(s, 0, 1, 1, 1, 0x284, 0x286, d3d_mh_scene_ambient_color);
  set_d3d_mh(s, 1, 0, 0, 0, 0x1ba, 0x1bd, d3d_mh_viewport_offset);
  set_d3d_mh(s, 0, 1, 1, 1, 0x288, 0x28b, d3d_mh_viewport_offset);
  set_d3d_mh(s, 0, 1, 1, 1, 0x294, 0x297, d3d_mh_eye_position);
  set_d3d_mh(s, 1, 0, 0, 0, 0x09c, 0x09d, d3d_mh_0096_09c);
  set_d3d_mh(s, 0, 1, 0, 0, 0x298, 0x2a7, d3d_mh_0097_298);
  set_d3d_mh(s, 1, 0, 0, 0, 0x09e, 0x09f, d3d_mh_combiner_alpha_ocw);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2a8, 0x2af, d3d_mh_combiner_alpha_ocw);
  set_d3d_mh(s, 1, 0, 0, 0, 0x09a, 0x09b, d3d_mh_combiner_color_icw);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2b0, 0x2b7, d3d_mh_combiner_color_icw);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2b8, 0x2bb, d3d_mh_texture_key_color);
  set_d3d_mh(s, 0, 0, 1, 1, 0x740, 0x74f, d3d_mh_texture_key_color);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2bc, 0x2bf, d3d_mh_viewport_scale);
  set_d3d_mh(s, 0, 0, 1, 1, 0x28c, 0x28f, d3d_mh_viewport_scale);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2c0, 0x2c3, d3d_mh_transform_program);
  set_d3d_mh(s, 0, 0, 1, 1, 0x2e0, 0x2e3, d3d_mh_transform_program);
  set_d3d_mh(s, 0, 1, 0, 0, 0x2e0, 0x2e3, d3d_mh_transform_constant);
  set_d3d_mh(s, 0, 0, 1, 1, 0x7c0, 0x7cf, d3d_mh_transform_constant);
  set_d3d_mh(s, 1, 0, 0, 0, 0x200, 0x2ff, d3d_mh_light);
  set_d3d_mh(s, 0, 1, 1, 1, 0x400, 0x4ff, d3d_mh_light);
  set_d3d_mh(s, 1, 0, 0, 0, 0x300, 0x302, d3d_mh_0096_300);
  set_d3d_mh(s, 0, 1, 0, 0, 0x540, 0x542, d3d_mh_0096_300);
  set_d3d_mh(s, 0, 0, 1, 1, 0x540, 0x57f, d3d_mh_0497_540);
  set_d3d_mh(s, 1, 0, 0, 0, 0x306, 0x309, d3d_mh_0096_306);
  set_d3d_mh(s, 0, 1, 0, 0, 0x546, 0x549, d3d_mh_0096_306);
  set_d3d_mh(s, 1, 0, 0, 0, 0x30c, 0x30e, d3d_mh_0096_30c);
  set_d3d_mh(s, 0, 1, 0, 0, 0x54c, 0x54e, d3d_mh_0096_30c);
  set_d3d_mh(s, 1, 0, 0, 0, 0x314, 0x317, d3d_mh_0096_314);
  set_d3d_mh(s, 0, 1, 0, 0, 0x554, 0x557, d3d_mh_0096_314);
  set_d3d_mh(s, 1, 0, 0, 0, 0x318, 0x31a, d3d_mh_0096_318);
  set_d3d_mh(s, 0, 1, 0, 0, 0x558, 0x55a, d3d_mh_0096_318);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x31b, d3d_mh_0096_31b);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x55b, d3d_mh_0096_31b);
  set_d3d_mh(s, 1, 0, 0, 0, 0x324, 0x337, d3d_mh_texcoord);
  set_d3d_mh(s, 0, 1, 0, 0, 0x564, 0x58b, d3d_mh_texcoord);
  set_d3d_mh(s, 0, 1, 0, 0, 0x5c8, 0x5d7, d3d_mh_0097_5c8);
  set_d3d_mh(s, 0, 0, 1, 1, 0x5a0, 0x5af, d3d_mh_0097_5c8);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x5cf, d3d_mh_vertex_data_base_index);
  set_d3d_mh(s, 1, 0, 0, 0, 0x340, 0x34f, d3d_mh_vertex_data_array_format);
  set_d3d_mh(s, 0, 1, 0, 0, 0x5d8, 0x5e7, d3d_mh_vertex_data_array_format);
  set_d3d_mh(s, 0, 0, 1, 1, 0x5d0, 0x5df, d3d_mh_vertex_data_array_format);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x5f4, d3d_mh_get_report);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x600, d3d_mh_get_report);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x37f, d3d_mh_begin_end);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x4ff, d3d_mh_begin_end);
  set_d3d_mh1(s, 1, 1, 0, 0, 0x5ff, d3d_mh_begin_end);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x602, d3d_mh_begin_end);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x380, d3d_mh_array_element16);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x600, d3d_mh_array_element16);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x603, d3d_mh_array_element16);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x440, d3d_mh_array_element32);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x602, d3d_mh_array_element32);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x604, d3d_mh_array_element32);
  set_d3d_mh1(s, 1, 0, 0, 0, 0x500, d3d_mh_draw_arrays);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x604, d3d_mh_draw_arrays);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x605, d3d_mh_draw_arrays);
  set_d3d_mh(s, 1, 0, 0, 0, 0x600, 0x6ff, d3d_mh_inline_array);
  set_d3d_mh1(s, 0, 1, 1, 1, 0x606, d3d_mh_inline_array);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x607, d3d_mh_index_array_offset);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x608, d3d_mh_index_array_dma);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x609, d3d_mh_0497_609);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x60a, d3d_mh_0097_60a);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x0e7, d3d_mh_0097_60a);
  set_d3d_mh(s, 0, 0, 1, 1, 0x610, 0x61f, d3d_mh_0497_610);
  set_d3d_mh(s, 0, 1, 1, 1, 0x620, 0x63f, d3d_mh_0097_620);
  set_d3d_mh(s, 0, 1, 1, 1, 0x640, 0x64f, d3d_mh_0097_640);
  set_d3d_mh(s, 0, 1, 1, 1, 0x650, 0x65f, d3d_mh_0097_650);
  set_d3d_mh(s, 0, 1, 0, 0, 0x680, 0x6bf, d3d_mh_0097_680);
  set_d3d_mh(s, 0, 0, 1, 1, 0x700, 0x73f, d3d_mh_0097_680);
  set_d3d_mh(s, 1, 0, 0, 0, 0x086, 0x095, d3d_mh_texture);
  set_d3d_mh(s, 0, 1, 0, 0, 0x6c0, 0x6ff, d3d_mh_texture);
  set_d3d_mh(s, 0, 0, 1, 1, 0x680, 0x6ff, d3d_mh_texture);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x758, d3d_mh_shader_control);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x75b, d3d_mh_semaphore_offset);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x75c, d3d_mh_75c);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x75d, d3d_mh_75d);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x763, d3d_mh_zstencil_clear_value);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x764, d3d_mh_color_clear_value);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x765, d3d_mh_clear_surface);
  set_d3d_mh(s, 1, 0, 0, 0, 0x0a0, 0x0a1, d3d_mh_combiner_color_ocw);
  set_d3d_mh(s, 0, 1, 0, 0, 0x790, 0x797, d3d_mh_combiner_color_ocw);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x798, d3d_mh_combiner_control);
  set_d3d_mh1(s, 0, 0, 1, 0, 0x23f, d3d_mh_combiner_control);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x79c, d3d_mh_tex_shader_op);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x79d, d3d_mh_tex_shader_dotmapping);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x79e, d3d_mh_tex_shader_previous);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x7a5, d3d_mh_transform_execution_mode);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x7a7, d3d_mh_transform_program_load);
  set_d3d_mh1(s, 1, 1, 1, 1, 0x7a8, d3d_mh_transform_program_start);
  set_d3d_mh1(s, 0, 1, 0, 0, 0x7a9, d3d_mh_transform_constant_load);
  set_d3d_mh1(s, 0, 0, 1, 1, 0x7bf, d3d_mh_transform_constant_load);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x7f1, d3d_mh_4097_7f1);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x7f2, d3d_mh_4097_7f2);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x7f3, d3d_mh_4097_7f3);
  set_d3d_mh1(s, 0, 0, 0, 1, 0x7fd, d3d_mh_4097_7fd);
}

void nv3d_execute_d3d(NV15State *s, gf_channel *ch, uint32_t cls, uint32_t method, uint32_t param)
{
  if (method >= GEFORCE_METHOD_COUNT) return;
  s->class_method_handlers[cls][method](s, ch, cls, method, param);
}
